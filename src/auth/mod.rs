use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};
use sha1::{Digest, Sha1};

const PGP_SIGNATURE_FOOTER: &str = "-----END PGP SIGNATURE-----";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrpProof {
    pub client_ephemeral: String,
    pub client_proof: String,
    pub expected_server_proof: String,
}

pub fn calculate_srp_proof(
    version: u64,
    _username: &str,
    password: &str,
    salt: &str,
    modulus: &str,
    server_ephemeral: &str,
) -> Result<SrpProof> {
    let version = match version {
        3 => SrpHashVersion::V3,
        4 => SrpHashVersion::V4,
        _ => bail!("unsupported Proton SRP auth version {version}"),
    };
    ensure_no_trailing_signed_modulus_data(modulus)?;

    let proof: SRPProofB64 =
        SRPAuth::with_pgp(None, password, version, salt, modulus, server_ephemeral)
            .context("failed to prepare Proton SRP authentication")?
            .generate_proofs()
            .context("failed to compute Proton SRP proof")?
            .into();

    Ok(SrpProof {
        client_ephemeral: proof.client_ephemeral,
        client_proof: proof.client_proof,
        expected_server_proof: proof.expected_server_proof,
    })
}

fn ensure_no_trailing_signed_modulus_data(modulus: &str) -> Result<()> {
    let Some((_, trailing)) = modulus.split_once(PGP_SIGNATURE_FOOTER) else {
        return Ok(());
    };
    if trailing.trim().is_empty() {
        return Ok(());
    }
    bail!("invalid SRP signed modulus: trailing data after signature")
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

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose};

    use super::*;

    const TEST_SERVER_EPHEMERAL: &str = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
    const TEST_SIGNED_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";

    #[test]
    fn calculates_base64_srp_fields_for_modern_proton() {
        let proof = calculate_srp_proof(
            4,
            "jakubqa",
            "abc123",
            "yKlc5/CvObfoiw==",
            TEST_SIGNED_MODULUS,
            TEST_SERVER_EPHEMERAL,
        )
        .unwrap();

        assert_eq!(
            general_purpose::STANDARD
                .decode(&proof.client_ephemeral)
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            general_purpose::STANDARD
                .decode(&proof.client_proof)
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            general_purpose::STANDARD
                .decode(&proof.expected_server_proof)
                .unwrap()
                .len(),
            256
        );
    }

    #[test]
    fn rejects_invalid_proton_signed_modulus_signature() {
        let invalid =
            TEST_SIGNED_MODULUS.replacen("GO86yMV4zDZEZcDSJo0fgr8A", "HO86yMV4zDZEZcDSJo0fgr8A", 1);
        let error = calculate_srp_proof(
            4,
            "alice",
            "password",
            "AQIDBAUGBwgJCg==",
            &invalid,
            TEST_SERVER_EPHEMERAL,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("Invalid SRP modulus"));
    }

    #[test]
    fn rejects_data_after_signed_modulus() {
        let error = calculate_srp_proof(
            4,
            "alice",
            "password",
            "AQIDBAUGBwgJCg==",
            &format!("{TEST_SIGNED_MODULUS}data after modulus"),
            TEST_SERVER_EPHEMERAL,
        )
        .unwrap_err();

        assert!(error.to_string().contains("invalid SRP signed modulus"));
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
