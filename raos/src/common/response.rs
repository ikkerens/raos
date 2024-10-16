use url::Url;

use crate::common::{OAuthError, PublicOAuthErrorBody};

/// The FrontendResponse enum is used to send responses back to the client.
/// This enum is used to send JSON responses, error responses, and redirects.
#[derive(Debug)]
pub enum FrontendResponse {
    /// A successful JSON response.
    Success {
        /// The JSON data to send back to the client.
        json: serde_json::Value,
    },
    /// An error response.
    Error {
        /// The error to send back to the client.
        error: PublicOAuthErrorBody,
    },
    /// A redirect response.
    Redirect {
        /// The location to redirect the client to.
        location: Url,
    },
}

/// The FrontendResponseExt trait is used to convert various response types like
/// [AuthorizationResponse](crate::authorize::AuthorizationResponse) and [TokenResponse](crate::token::TokenResponse)
/// into a [FrontendResponse].
///
/// This trait is implemented for [Result<R, OAuthError<E>>](OAuthError) where R implements FrontendResponseExt.
pub trait FrontendResponseExt {
    /// Convert the response into a FrontendResponse.
    fn into_frontend_response(self) -> FrontendResponse;
}

impl<R, E> FrontendResponseExt for Result<R, OAuthError<E>>
where
    R: FrontendResponseExt,
{
    fn into_frontend_response(self) -> FrontendResponse {
        // Convert the result into a FrontendResponse
        match self {
            Ok(r) => r.into_frontend_response(),
            Err(e) => e.into_frontend_response(),
        }
    }
}
