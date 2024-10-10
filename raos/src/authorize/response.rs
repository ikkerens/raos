use serde::Serialize;
use url::Url;

use crate::common::{FrontendResponse, FrontendResponseExt, PublicOAuthError};

/// The response to an authorization request.
/// This struct contains the authorization code and state to be sent back to the client.
/// This struct implements the [FrontendResponseExt] trait to allow it to be converted into a
/// [FrontendResponse] that can be sent back to the client.
/// This struct is serialized into a query string to be appended to the redirect URI.
#[derive(Serialize)]
pub struct AuthorizationResponse {
    /// The authorization code to be sent back to the client.
    pub code: String,
    /// The state to be sent back to the client, which should be the same as the one sent in the request.
    pub state: Option<String>,
    /// The issuer of the authorization code, if it is different from the authorization server.
    pub iss: Option<String>,

    /// The redirect URI to send the response to, which should match the one sent in the request.
    /// Or, if it was not provided in the request, the only redirect URI the client has registered.
    #[serde(skip)]
    pub redirect_uri: Url,
}

impl FrontendResponseExt for AuthorizationResponse {
    fn into_frontend_response(self) -> FrontendResponse {
        // Serialize the struct into a query string
        let Ok(url_params) = serde_urlencoded::to_string(&self) else {
            return FrontendResponse::Error { error: PublicOAuthError::ServerError.into() };
        };

        // Append the query string to the redirect URI
        let mut location = self.redirect_uri;
        let full_params = if let Some(existing) = location.query() {
            format!("{}&{}", existing, url_params)
        } else {
            url_params
        };
        location.set_query(Some(&full_params));

        // Return a redirect response
        FrontendResponse::Redirect { location }
    }
}
