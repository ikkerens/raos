use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::model::CodeChallenge;

/// A grant is used to send information to and from the providers for the library to work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant<OwnerId> {
    /// The OAuth resource owner's id.
    pub owner_id: OwnerId,
    /// The client id of the client making the request.
    pub client_id: String,
    /// The scopes requested by the client.
    pub scope: Vec<String>,
    /// The selected redirect uri of the client.
    pub redirect_uri: Url,
    /// The code challenge used in PKCE.
    pub code_challenge: CodeChallenge,
}
