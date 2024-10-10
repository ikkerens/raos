use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The code challenge used in PKCE.
/// This enum represents the different types of code challenges that can be used in PKCE.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CodeChallenge {
    /// No code challenge is used.
    None,
    /// A plain code challenge is used.
    Plain {
        /// The plain-text code challenge sent by the client.
        code_challenge: String,
    },
    /// A S256 code challenge is used.
    S256 {
        /// The SHA-256 code challenge hashed and sent by the client.
        code_challenge: String,
    },
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

#[cfg(test)]
mod test {
    #[test]
    fn test_code_challenge_verify() {
        use super::CodeChallenge;

        let plain_challenge = CodeChallenge::Plain { code_challenge: "verifier".to_string() };
        let s256_challenge = CodeChallenge::S256 {
            // This is the correct challenge for the verifier "code_challenge".
            code_challenge: "qoJXAtQ-gjzfDmoMrHt1a2AFVe1Tn3-HX0VC2_UtezA".to_string(),
        };

        assert!(plain_challenge.verify("verifier"));
        assert!(!plain_challenge.verify("wrong_verifier"));
        assert!(!plain_challenge.verify(""));

        assert!(s256_challenge.verify("code_challenge"));
        assert!(!s256_challenge.verify("wrong_code_challenge"));
        assert!(!s256_challenge.verify(""));
    }
}
