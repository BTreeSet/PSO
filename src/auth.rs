use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use num_bigint::BigUint;
use num_traits::One;
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrpProof {
    pub client_ephemeral: String,
    pub client_proof: String,
}

pub fn calculate_srp_proof(
    username: &str,
    password: &str,
    salt_base64: &str,
    modulus_hex: &str,
    server_ephemeral_hex: &str,
) -> Result<SrpProof> {
    let modulus = decode_hex_biguint(modulus_hex).context("invalid SRP modulus")?;
    let server_ephemeral =
        decode_hex_biguint(server_ephemeral_hex).context("invalid SRP server ephemeral")?;
    if modulus <= BigUint::one() || server_ephemeral >= modulus {
        bail!("invalid SRP server parameters");
    }

    let generator = BigUint::from(2_u8);
    let salt = general_purpose::STANDARD
        .decode(salt_base64)
        .context("invalid SRP salt")?;
    let modulus_len = modulus.to_bytes_be().len();

    let mut private_ephemeral_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut private_ephemeral_bytes);
    let private_ephemeral = BigUint::from_bytes_be(&private_ephemeral_bytes);
    let client_ephemeral = generator.modpow(&private_ephemeral, &modulus);

    let password_hash = expand_password(username, password, &salt)?;
    let x = hash_to_biguint(&[&salt, password_hash.as_bytes()]);
    let k = hash_to_biguint(&[
        &pad_biguint(&modulus, modulus_len),
        &pad_biguint(&generator, modulus_len),
    ]);
    let u = hash_to_biguint(&[
        &pad_biguint(&client_ephemeral, modulus_len),
        &pad_biguint(&server_ephemeral, modulus_len),
    ]);

    let gx = generator.modpow(&x, &modulus);
    let kgx = (k * gx) % &modulus;
    let base = if server_ephemeral >= kgx {
        (&server_ephemeral - kgx) % &modulus
    } else {
        (&server_ephemeral + &modulus - kgx) % &modulus
    };
    let exponent = private_ephemeral + (u * x);
    let shared_secret = base.modpow(&exponent, &modulus);

    let proof = sha256_concat(&[
        &pad_biguint(&client_ephemeral, modulus_len),
        &pad_biguint(&server_ephemeral, modulus_len),
        &pad_biguint(&shared_secret, modulus_len),
    ]);

    Ok(SrpProof {
        client_ephemeral: hex::encode(pad_biguint(&client_ephemeral, modulus_len)),
        client_proof: hex::encode(proof),
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

fn expand_password(username: &str, password: &str, salt: &[u8]) -> Result<String> {
    let salt_b64 = general_purpose::STANDARD.encode(salt);
    let expanded = format!("{username}:{password}:{salt_b64}");
    bcrypt::hash(expanded, bcrypt::DEFAULT_COST).context("failed to expand password with bcrypt")
}

fn decode_hex_biguint(value: &str) -> Result<BigUint> {
    let cleaned = value
        .trim()
        .trim_start_matches("0x")
        .replace([' ', '\n'], "");
    let bytes = hex::decode(cleaned)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn hash_to_biguint(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&sha256_concat(parts))
}

fn sha256_concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn pad_biguint(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= len {
        return bytes;
    }
    let mut padded = vec![0_u8; len - bytes.len()];
    padded.extend(bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_nonempty_srp_fields() {
        let proof = calculate_srp_proof(
            "alice@example.com",
            "correct horse battery staple",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "E487EBF59785F6762FD7B88B",
            "8F1BC32A7D19E193AF2E41D2",
        )
        .unwrap();

        assert!(!proof.client_ephemeral.is_empty());
        assert_eq!(proof.client_proof.len(), 64);
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
