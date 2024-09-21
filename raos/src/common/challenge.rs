use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CodeChallenge {
    None,
    Plain { code_challenge: String },
    S256 { code_challenge: String },
}

impl CodeChallenge {
    pub(crate) fn verify(&self, verifier: &str) -> bool {
        match self {
            Self::None => true,
            Self::Plain { code_challenge } => {
                verifier.as_bytes().ct_eq(code_challenge.as_bytes()).into()
            }
            Self::S256 { code_challenge } => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());
                code_verifier.as_bytes().ct_eq(code_challenge.as_bytes()).into()
            }
        }
    }
}
