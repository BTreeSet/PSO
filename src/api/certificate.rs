use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateRequest {
    #[serde(rename = "ClientPublicKey")]
    pub client_public_key: String,
    #[serde(rename = "DeviceName")]
    pub device_name: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "Features")]
    pub features: CertificateFeatures,
    #[serde(
        rename = "ClientPublicKeyMode",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_public_key_mode: Option<String>,
    #[serde(rename = "Duration", skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    #[serde(rename = "Renew", skip_serializing_if = "Option::is_none")]
    pub renew: Option<bool>,
}

impl CertificateRequest {
    pub fn wireguard_session(
        client_public_key: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            client_public_key: client_public_key.into(),
            device_name: device_name.into(),
            mode: "session".into(),
            features: CertificateFeatures::Empty(Vec::new()),
            client_public_key_mode: Some("EC".into()),
            duration: None,
            renew: None,
        }
    }

    pub fn persistent_wireguard(
        client_public_key: impl Into<String>,
        device_name: impl Into<String>,
        features: PersistentCertificateFeatures,
        renew: bool,
    ) -> Result<Self> {
        let client_public_key = client_public_key.into();
        let client_public_key = if renew {
            pem_encode_x25519_public_key(&client_public_key)?
        } else {
            client_public_key
        };

        Ok(Self {
            client_public_key,
            device_name: device_name.into(),
            mode: "persistent".into(),
            features: CertificateFeatures::Persistent(features),
            client_public_key_mode: None,
            duration: None,
            renew: renew.then_some(true),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CertificateFeatures {
    Empty(Vec<String>),
    Persistent(PersistentCertificateFeatures),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentCertificateFeatures {
    #[serde(rename = "Bouncing")]
    pub bouncing: String,
    #[serde(rename = "PortForwarding")]
    pub port_forwarding: bool,
    #[serde(rename = "SplitTCP")]
    pub split_tcp: bool,
    #[serde(rename = "peerName")]
    pub peer_name: String,
    #[serde(rename = "peerIp")]
    pub peer_ip: String,
    #[serde(rename = "peerPublicKey")]
    pub peer_public_key: String,
    #[serde(rename = "platform")]
    pub platform: String,
}

impl PersistentCertificateFeatures {
    pub fn proton(
        peer_name: impl Into<String>,
        peer_ip: impl Into<String>,
        peer_public_key: impl Into<String>,
    ) -> Self {
        Self {
            bouncing: "0".into(),
            port_forwarding: false,
            split_tcp: true,
            peer_name: peer_name.into(),
            peer_ip: peer_ip.into(),
            peer_public_key: peer_public_key.into(),
            platform: "Android".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SessionLocalKeyBody {
    pub key: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SessionPayloadBody {
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CertificateListResponse {
    Bare(Vec<CertificateResponse>),
    Wrapped {
        #[serde(
            alias = "Certificates",
            alias = "Certificate",
            alias = "Items",
            default
        )]
        certificates: Vec<CertificateResponse>,
    },
}

impl CertificateListResponse {
    pub fn into_certificates(self) -> Vec<CertificateResponse> {
        match self {
            Self::Bare(certificates) => certificates,
            Self::Wrapped { certificates } => certificates,
        }
    }
}

fn pem_encode_x25519_public_key(raw_public_key_base64: &str) -> Result<String> {
    let public_key = general_purpose::STANDARD
        .decode(raw_public_key_base64)
        .context("invalid Proton X25519 public key")?;
    let mut der = Vec::with_capacity(12 + public_key.len());
    der.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ]);
    der.extend_from_slice(&public_key);
    let encoded = general_purpose::STANDARD.encode(der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\r\n{encoded}\r\n-----END PUBLIC KEY-----"
    ))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CertificateResponse {
    #[serde(alias = "Certificate", alias = "certificate")]
    pub certificate: String,
    #[serde(
        default,
        alias = "SerialNumber",
        alias = "serialNumber",
        alias = "serial_number",
        alias = "ProfileID",
        alias = "profileId",
        alias = "profile_id",
        alias = "ID",
        alias = "Id",
        alias = "id"
    )]
    pub profile_id: Option<String>,
    #[serde(
        default,
        alias = "ExpirationTimeMs",
        alias = "expirationTimeMs",
        alias = "expiration_time_ms"
    )]
    expiration_time_ms: Option<u64>,
    #[serde(default, alias = "ExpirationTime", alias = "expiration_time")]
    expiration_time: Option<u64>,
    #[serde(
        default,
        alias = "RefreshTimeMs",
        alias = "refreshTimeMs",
        alias = "refresh_time_ms"
    )]
    refresh_time_ms: Option<u64>,
    #[serde(default, alias = "RefreshTime", alias = "refresh_time")]
    refresh_time: Option<u64>,
    #[serde(
        default,
        alias = "AssignedIP",
        alias = "AssignedIp",
        alias = "assignedIp",
        alias = "assigned_ip"
    )]
    pub assigned_ip: Option<String>,
    #[serde(default, alias = "Endpoint", alias = "endpoint")]
    pub endpoint: Option<String>,
    #[serde(
        default,
        alias = "ClientPublicKey",
        alias = "clientPublicKey",
        alias = "client_public_key"
    )]
    pub client_public_key: Option<String>,
    #[serde(
        default,
        alias = "PeerPublicKey",
        alias = "peerPublicKey",
        alias = "peer_public_key"
    )]
    pub peer_public_key: Option<String>,
}

impl CertificateResponse {
    pub fn expiration_time_ms(&self) -> Result<u64> {
        self.expiration_time_ms
            .or_else(|| {
                self.expiration_time
                    .map(|seconds| seconds.saturating_mul(1000))
            })
            .context(
                "Proton certificate response did not include ExpirationTime or ExpirationTimeMs",
            )
    }

    pub fn refresh_time_ms(&self) -> Result<u64> {
        self.refresh_time_ms
            .or_else(|| {
                self.refresh_time
                    .map(|seconds| seconds.saturating_mul(1000))
            })
            .context("Proton certificate response did not include RefreshTime or RefreshTimeMs")
    }

    pub fn matches_client_public_key(&self, expected_raw_base64: &str) -> bool {
        self.client_public_key
            .as_deref()
            .and_then(extract_raw_x25519_public_key_base64)
            .is_some_and(|profile_key| profile_key == expected_raw_base64)
    }
}

fn extract_raw_x25519_public_key_base64(input: &str) -> Option<String> {
    // SubjectPublicKeyInfo DER prefix for X25519 (OID 1.3.101.112)
    const X25519_DER_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let sanitized = input
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    if sanitized.is_empty() {
        return None;
    }

    let decoded = general_purpose::STANDARD
        .decode(sanitized.as_bytes())
        .ok()?;
    if decoded.len() == 32 {
        return Some(general_purpose::STANDARD.encode(decoded));
    }

    let raw = decoded.strip_prefix(&X25519_DER_PREFIX)?;
    if raw.len() != 32 {
        return None;
    }
    Some(general_purpose::STANDARD.encode(raw))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DUMMY_X25519_PUBLIC_KEY_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const DUMMY_PEER_PUBLIC_KEY: &str = "dumb-peer-public-key";

    #[test]
    fn serializes_certificate_request_like_proton_client() {
        let request = CertificateRequest::wireguard_session("public-key", "PSO-Rust-Control-Plane");
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["ClientPublicKey"], "public-key");
        assert_eq!(value["ClientPublicKeyMode"], "EC");
        assert_eq!(value["DeviceName"], "PSO-Rust-Control-Plane");
        assert_eq!(value["Mode"], "session");
        assert_eq!(value["Features"], json!([]));
        assert!(value.get("Renew").is_none());
    }

    #[test]
    fn serializes_persistent_certificate_request_like_browser_client() {
        let request = CertificateRequest::persistent_wireguard(
            DUMMY_X25519_PUBLIC_KEY_BASE64,
            "f983fc5f-b834-41ae-97c4-ee49e2c46153",
            PersistentCertificateFeatures::proton(
                "DUMMY-FREE#1",
                "198.51.100.10",
                DUMMY_PEER_PUBLIC_KEY,
            ),
            true,
        )
        .unwrap();
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["Mode"], "persistent");
        assert_eq!(value["DeviceName"], "f983fc5f-b834-41ae-97c4-ee49e2c46153");
        assert_eq!(value["Renew"], json!(true));
        assert_eq!(
            value["ClientPublicKey"],
            pem_encode_x25519_public_key(DUMMY_X25519_PUBLIC_KEY_BASE64).unwrap()
        );
        assert_eq!(value["Features"]["Bouncing"], "0");
        assert_eq!(value["Features"]["peerName"], "DUMMY-FREE#1");
        assert_eq!(value["Features"]["peerIp"], "198.51.100.10");
        assert_eq!(value["Features"]["platform"], "Android");
    }

    #[test]
    fn serializes_browser_session_maintenance_bodies_like_proton_client() {
        let local_key = serde_json::to_value(SessionLocalKeyBody {
            key: "dumb-session-key".into(),
        })
        .unwrap();
        assert_eq!(local_key["Key"], "dumb-session-key");

        let payload = serde_json::to_value(SessionPayloadBody {
            payload: json!({
                ".-77VX-aP0iPqoI": "dumb-encrypted-payload"
            }),
        })
        .unwrap();
        assert_eq!(
            payload["Payload"][".-77VX-aP0iPqoI"],
            "dumb-encrypted-payload"
        );
    }

    #[test]
    fn deserializes_certificate_list_response_shapes() {
        let wrapped: CertificateListResponse = serde_json::from_value(json!({
            "Certificates": [{
                "Certificate": "cert-pem",
                "ExpirationTime": 2,
                "RefreshTime": 1,
                "AssignedIP": "10.2.0.2/32"
            }]
        }))
        .unwrap();
        assert_eq!(wrapped.into_certificates().len(), 1);

        let bare: CertificateListResponse = serde_json::from_value(json!([{
            "Certificate": "cert-pem",
            "ExpirationTime": 2,
            "RefreshTime": 1,
            "AssignedIP": "10.2.0.2/32"
        }]))
        .unwrap();
        assert_eq!(bare.into_certificates().len(), 1);
    }

    #[test]
    fn matches_client_public_key_from_pem_profile_shape() {
        let certificate: CertificateResponse = serde_json::from_value(json!({
            "Certificate": "dummy",
            "ExpirationTime": 1,
            "RefreshTime": 1,
            "ClientPublicKey": "-----BEGIN PUBLIC KEY-----\r\nMCowBQYDK2VwAyEAgTaZvmRLXpjg8ajCWICHrp6AbeC/o/pDco1LN5tiDkk=\r\n-----END PUBLIC KEY-----"
        }))
        .unwrap();

        assert!(
            certificate.client_public_key.is_some(),
            "client_public_key should be deserialized"
        );
        assert!(
            certificate.matches_client_public_key("gTaZvmRLXpjg8ajCWICHrp6AbeC/o/pDco1LN5tiDkk="),
            "client_public_key was: {:?}",
            certificate.client_public_key
        );
    }

    #[test]
    fn accepts_common_certificate_response_shapes() {
        let response: CertificateResponse = serde_json::from_value(json!({
            "Certificate": "cert-pem",
            "ExpirationTime": 2,
            "RefreshTime": 1,
            "AssignedIP": "10.2.0.2/32"
        }))
        .unwrap();

        assert_eq!(response.certificate, "cert-pem");
        assert_eq!(response.expiration_time_ms().unwrap(), 2000);
        assert_eq!(response.refresh_time_ms().unwrap(), 1000);
        assert_eq!(response.assigned_ip.as_deref(), Some("10.2.0.2/32"));
    }
}
