use serde::{
    ser::SerializeStruct,
    Serialize,
    Serializer,
};
use url::Url;

use crate::common::{FrontendResponse, FrontendResponseExt, PublicOAuthError};

/// The response to an authorization request.
/// This struct contains the authorization result, optional state and optional server identifier to be sent back to the client.
/// The result will either contain a code, or an error to send back to the client.
///
/// This struct implements the [FrontendResponseExt] trait to allow it to be converted into a
/// [FrontendResponse] that can be sent back to the client.
/// This struct is serialized into a query string to be appended to the redirect URI.
#[derive(Serialize)]
pub struct AuthorizationResponse {
    /// The authorization result to be sent back to the client.
    /// This will either contain a code, or an error to send back to the client.
    #[serde(flatten, serialize_with = "serialize_result")]
    pub result: Result<String, PublicOAuthError>,
    /// The state to be sent back to the client, which should be the same as the one sent in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The issuer of the authorization code, if it is different from the authorization server.
    #[serde(skip_serializing_if = "Option::is_none")]
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

fn serialize_result<S>(
    result: &Result<String, PublicOAuthError>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("AuthorizationResult", 2)?;
    match result {
        Ok(code) => state.serialize_field("code", code)?,
        Err(error) => {
            state.serialize_field("error", &error.to_string())?;
            state.serialize_field("error_description", &error.to_description())?;
        }
    }

    state.end()
}
