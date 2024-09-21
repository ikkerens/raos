use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::CodeChallenge;

#[derive(Clone, Serialize, Deserialize)]
pub struct Grant<OwnerId> {
    pub owner_id: OwnerId,
    pub client_id: String,
    pub scope: Vec<String>,
    pub redirect_uri: Url,
    pub code_challenge: CodeChallenge,
}
