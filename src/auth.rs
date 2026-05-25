use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use bcrypt::Version;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha512};

const SRP_LEN: usize = 2048 / 8;
const MAX_VALUE_ITERATIONS: usize = 1000;
const BCRYPT_COST: u32 = 10;
const BCRYPT_SALT_SUFFIX: &[u8] = b"proton";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrpProof {
    pub client_ephemeral: String,
    pub client_proof: String,
    pub expected_server_proof: String,
}

pub fn calculate_srp_proof(
    version: u64,
    username: &str,
    password: &str,
    salt: &str,
    modulus: &str,
    server_ephemeral: &str,
) -> Result<SrpProof> {
    calculate_srp_proof_with_secret(
        version,
        username,
        password,
        salt,
        modulus,
        server_ephemeral,
        None,
    )
}

fn calculate_srp_proof_with_secret(
    version: u64,
    _username: &str,
    password: &str,
    salt: &str,
    modulus: &str,
    server_ephemeral: &str,
    client_secret_override: Option<&[u8]>,
) -> Result<SrpProof> {
    if !matches!(version, 3 | 4) {
        bail!("unsupported Proton SRP auth version {version}");
    }

    let modulus_bytes = decode_modulus(modulus)?;
    let server_ephemeral_bytes = decode_binary_value(server_ephemeral, "SRP server ephemeral")?;
    let salt_bytes = decode_binary_value(salt, "SRP salt")?;

    let hashed_password = hash_password(version, password, &salt_bytes, &modulus_bytes)?;
    let proofs = generate_proofs(
        &modulus_bytes,
        &server_ephemeral_bytes,
        &hashed_password,
        client_secret_override,
    )?;

    Ok(SrpProof {
        client_ephemeral: general_purpose::STANDARD.encode(proofs.client_ephemeral),
        client_proof: general_purpose::STANDARD.encode(proofs.client_proof),
        expected_server_proof: general_purpose::STANDARD.encode(proofs.expected_server_proof),
    })
}

pub fn resolve_two_factor_code(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.len() == 6 && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(trimmed.to_string());
    }

    let secret = extract_totp_secret(trimmed);
    let key = decode_base32_secret(&secret)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    generate_totp_code(&key, now, 30, 6)
}

struct GeneratedProofs {
    client_ephemeral: Vec<u8>,
    client_proof: Vec<u8>,
    expected_server_proof: Vec<u8>,
}

fn decode_modulus(value: &str) -> Result<Vec<u8>> {
    let bytes = decode_binary_value(value, "SRP modulus")?;
    if bytes.len() != SRP_LEN {
        bail!("SRP modulus has incorrect size");
    }
    Ok(bytes)
}

fn decode_binary_value(value: &str, label: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        let payload = extract_clearsigned_payload(trimmed)?;
        return decode_base64_value(&payload, label);
    }

    let compact = strip_ascii_whitespace(trimmed);
    if is_hex_string(&compact) {
        return hex::decode(&compact).with_context(|| format!("invalid {label}"));
    }

    decode_base64_value(&compact, label)
}

fn decode_base64_value(value: &str, label: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .with_context(|| format!("invalid {label}"))
}

fn extract_clearsigned_payload(message: &str) -> Result<String> {
    let normalized = message.replace("\r\n", "\n");
    let signature_index = normalized
        .find("-----BEGIN PGP SIGNATURE-----")
        .context("invalid SRP signed modulus: missing signature")?;
    let header_end = normalized
        .find("\n\n")
        .context("invalid SRP signed modulus: missing cleartext body")?;
    let cleartext = &normalized[header_end + 2..signature_index];
    let payload = cleartext
        .lines()
        .filter(|line| !line.starts_with("Hash:"))
        .map(|line| line.strip_prefix("- ").unwrap_or(line))
        .collect::<String>();
    let payload = strip_ascii_whitespace(&payload);
    if payload.is_empty() {
        bail!("invalid SRP signed modulus: empty cleartext payload");
    }
    Ok(payload)
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

fn is_hex_string(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

fn hash_password(version: u64, password: &str, salt: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    match version {
        3 | 4 => hash_password_v3(password, salt, modulus),
        _ => bail!("unsupported Proton SRP auth version {version}"),
    }
}

fn hash_password_v3(password: &str, salt: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    let mut bcrypt_salt = Vec::with_capacity(salt.len() + BCRYPT_SALT_SUFFIX.len());
    bcrypt_salt.extend_from_slice(salt);
    bcrypt_salt.extend_from_slice(BCRYPT_SALT_SUFFIX);
    if bcrypt_salt.len() != 16 {
        bail!(
            "invalid Proton SRP salt length {}; expected 10 bytes",
            salt.len()
        );
    }

    let mut raw_salt = [0_u8; 16];
    raw_salt.copy_from_slice(&bcrypt_salt);

    let formatted = bcrypt::hash_with_salt(password, BCRYPT_COST, raw_salt)
        .context("failed to hash Proton password with bcrypt")?
        .format_for_version(Version::TwoY);

    Ok(expand_hash(&[formatted.as_bytes(), modulus]))
}

fn generate_proofs(
    modulus_bytes: &[u8],
    server_ephemeral_bytes: &[u8],
    hashed_password_bytes: &[u8],
    client_secret_override: Option<&[u8]>,
) -> Result<GeneratedProofs> {
    let modulus = BigUint::from_bytes_le(modulus_bytes);
    if modulus.to_bytes_le().len() != SRP_LEN {
        bail!("SRP modulus has incorrect size");
    }

    let generator = BigUint::from(2_u8);
    let generator_bytes = to_fixed_le_bytes(&generator, SRP_LEN)?;
    let multiplier = BigUint::from_bytes_le(&expand_hash(&[&generator_bytes, modulus_bytes]));
    let multiplier_reduced = &multiplier % &modulus;

    let server_ephemeral = BigUint::from_bytes_le(server_ephemeral_bytes);
    if server_ephemeral.is_zero() {
        bail!("SRP server ephemeral is out of bounds");
    }

    let hashed_password = BigUint::from_bytes_le(hashed_password_bytes);
    let modulus_minus_one = &modulus - BigUint::one();

    let (client_secret, client_ephemeral_bytes, scrambling_param) = get_safe_parameters(
        &generator,
        &modulus,
        server_ephemeral_bytes,
        client_secret_override,
    )?;

    let g_pow_x = generator.modpow(&hashed_password, &modulus);
    let kgx = (&multiplier_reduced * g_pow_x) % &modulus;
    let shared_session_exponent =
        ((&scrambling_param * &hashed_password) + &client_secret) % &modulus_minus_one;
    let shared_session_base = mod_sub(&server_ephemeral, &kgx, &modulus);
    let shared_session = shared_session_base.modpow(&shared_session_exponent, &modulus);
    let shared_session_bytes = to_fixed_le_bytes(&shared_session, SRP_LEN)?;

    let client_proof = expand_hash(&[
        &client_ephemeral_bytes,
        server_ephemeral_bytes,
        &shared_session_bytes,
    ]);
    let expected_server_proof = expand_hash(&[
        &client_ephemeral_bytes,
        &client_proof,
        &shared_session_bytes,
    ]);

    Ok(GeneratedProofs {
        client_ephemeral: client_ephemeral_bytes,
        client_proof,
        expected_server_proof,
    })
}

fn get_safe_parameters(
    generator: &BigUint,
    modulus: &BigUint,
    server_ephemeral_bytes: &[u8],
    client_secret_override: Option<&[u8]>,
) -> Result<(BigUint, Vec<u8>, BigUint)> {
    for attempt in 0..MAX_VALUE_ITERATIONS {
        let client_secret = match (attempt, client_secret_override) {
            (0, Some(bytes)) => BigUint::from_bytes_le(bytes),
            _ => generate_client_secret(),
        };
        let client_ephemeral = generator.modpow(&client_secret, modulus);
        let client_ephemeral_bytes = to_fixed_le_bytes(&client_ephemeral, SRP_LEN)?;
        let scrambling_param = BigUint::from_bytes_le(&expand_hash(&[
            &client_ephemeral_bytes,
            server_ephemeral_bytes,
        ]));

        if !client_ephemeral.is_zero() && !scrambling_param.is_zero() {
            return Ok((client_secret, client_ephemeral_bytes, scrambling_param));
        }

        if client_secret_override.is_some() {
            break;
        }
    }

    bail!("Could not find safe SRP parameters")
}

fn generate_client_secret() -> BigUint {
    let mut bytes = [0_u8; SRP_LEN];
    OsRng.fill_bytes(&mut bytes);
    BigUint::from_bytes_le(&bytes)
}

fn to_fixed_le_bytes(value: &BigUint, len: usize) -> Result<Vec<u8>> {
    let mut bytes = value.to_bytes_le();
    if bytes.len() > len {
        bail!("SRP value exceeds expected size");
    }
    bytes.resize(len, 0);
    Ok(bytes)
}

fn expand_hash(parts: &[&[u8]]) -> Vec<u8> {
    let total_len = parts.iter().map(|part| part.len()).sum::<usize>();
    let mut input = Vec::with_capacity(total_len);
    for part in parts {
        input.extend_from_slice(part);
    }

    let mut output = Vec::with_capacity(64 * 4);
    for index in 0..4_u8 {
        let mut hasher = Sha512::new();
        hasher.update(&input);
        hasher.update([index]);
        output.extend_from_slice(&hasher.finalize());
    }
    output
}

fn mod_sub(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        (lhs - rhs) % modulus
    } else {
        (lhs + modulus - rhs) % modulus
    }
}

fn extract_totp_secret(input: &str) -> String {
    if input.starts_with("otpauth://")
        && let Some((_, query)) = input.split_once('?')
    {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=')
                && key.eq_ignore_ascii_case("secret")
            {
                return value.to_string();
            }
        }
    }
    input.to_string()
}

fn generate_totp_code(key: &[u8], unix_time: u64, step: u64, digits: u32) -> Result<String> {
    if key.is_empty() {
        bail!("TOTP secret is empty");
    }
    let counter = unix_time / step;
    let digest = hmac_sha1(key, &counter.to_be_bytes());
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    let modulus = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = digits as usize
    ))
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        let digest = Sha1::digest(key);
        key_block[..20].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut outer = [0x5c_u8; 64];
    let mut inner = [0x36_u8; 64];
    for index in 0..64 {
        outer[index] ^= key_block[index];
        inner[index] ^= key_block[index];
    }

    let mut inner_hasher = Sha1::new();
    inner_hasher.update(inner);
    inner_hasher.update(message);
    let inner_digest = inner_hasher.finalize();

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(outer);
    outer_hasher.update(inner_digest);
    let digest = outer_hasher.finalize();

    let mut output = [0_u8; 20];
    output.copy_from_slice(&digest);
    output
}

fn decode_base32_secret(input: &str) -> Result<Vec<u8>> {
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    let mut output = Vec::new();

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            b'=' | b' ' | b'-' => continue,
            _ => bail!("TOTP secret must be base32 or a six-digit one-time code"),
        } as u32;

        bits = (bits << 5) | value;
        bit_count += 5;
        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_sized_signed_modulus_payload() {
        let error = decode_modulus(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nAQID\n-----BEGIN PGP SIGNATURE-----\nignored\n-----END PGP SIGNATURE-----",
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "SRP modulus has incorrect size");
    }

    #[test]
    fn hashes_password_deterministically_for_v4() {
        let salt = b"1234567890";
        let modulus = vec![0x7f_u8; SRP_LEN];

        let first = hash_password(4, "correct horse battery staple", salt, &modulus).unwrap();
        let second = hash_password(4, "correct horse battery staple", salt, &modulus).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 256);
    }

    #[test]
    fn calculates_base64_srp_fields_for_modern_proton() {
        let modulus = vec![0x7f_u8; SRP_LEN];
        let server_ephemeral = vec![0x05_u8; SRP_LEN];
        let salt = b"1234567890";
        let client_secret = [0x11_u8; 32];

        let proof = calculate_srp_proof_with_secret(
            4,
            "alice@example.com",
            "correct horse battery staple",
            &general_purpose::STANDARD.encode(salt),
            &general_purpose::STANDARD.encode(&modulus),
            &general_purpose::STANDARD.encode(&server_ephemeral),
            Some(&client_secret),
        )
        .unwrap();

        assert_eq!(
            decode_base64_value(&proof.client_ephemeral, "client ephemeral")
                .unwrap()
                .len(),
            SRP_LEN
        );
        assert_eq!(
            decode_base64_value(&proof.client_proof, "client proof")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            decode_base64_value(&proof.expected_server_proof, "server proof")
                .unwrap()
                .len(),
            256
        );
    }

    #[test]
    fn rejects_unsupported_auth_versions() {
        let error =
            calculate_srp_proof(2, "alice", "password", "AQID", "AQID", "AQID").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported Proton SRP auth version")
        );
    }

    #[test]
    fn accepts_six_digit_two_factor_code() {
        assert_eq!(resolve_two_factor_code("123456").unwrap(), "123456");
    }

    #[test]
    fn derives_totp_from_base32_secret() {
        let key = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(generate_totp_code(&key, 59, 30, 6).unwrap(), "287082");
    }
}
