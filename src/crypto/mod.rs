use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMaterial {
    pub private_key_base64: String,
    pub public_key_base64: String,
}

pub fn generate_key_material() -> KeyMaterial {
    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    KeyMaterial {
        private_key_base64: BASE64.encode(private_key.to_bytes()),
        public_key_base64: BASE64.encode(public_key.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::*;

    #[test]
    fn generates_wireguard_sized_keys() {
        let material = generate_key_material();
        assert_eq!(
            BASE64.decode(material.private_key_base64).unwrap().len(),
            32
        );
        assert_eq!(BASE64.decode(material.public_key_base64).unwrap().len(), 32);
    }
}
