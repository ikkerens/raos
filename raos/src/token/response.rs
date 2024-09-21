use serde::Serialize;

use crate::common::{FrontendResponse, FrontendResponseExt};

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl FrontendResponseExt for TokenResponse {
    fn into_frontend_response(self) -> FrontendResponse {
        FrontendResponse::Success { json: serde_json::to_value(self).unwrap() }
    }
}
