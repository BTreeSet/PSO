use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use num_bigint::BigUint;
use num_traits::One;
use rand_core::{OsRng, RngCore};
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
}
