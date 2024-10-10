use serde::Serialize;

use crate::common::{FrontendResponse, FrontendResponseExt};

/// The response to a token request.
#[derive(Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// The token type.
    pub token_type: String,
    /// The time in seconds until the token expires.
    pub expires_in: u64,
    /// The scope of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The refresh token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl FrontendResponseExt for TokenResponse {
    fn into_frontend_response(self) -> FrontendResponse {
        FrontendResponse::Success { json: serde_json::to_value(self).unwrap() }
    }
}
