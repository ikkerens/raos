use url::Url;

use crate::common::{OAuthError, PublicOAuthError, PublicOAuthErrorBody};

pub enum FrontendResponse {
    Success { json: serde_json::Value },
    Error { error: PublicOAuthErrorBody },
    Redirect { location: Url },
}

pub trait FrontendResponseExt {
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
            Err(e) => {
                // TODO Some errors require a redirect back to the client, whereas some others require a message to the resource owner, this needs to be implemented
                let error: PublicOAuthError = e.into();
                FrontendResponse::Error { error: error.into() }
            }
        }
    }
}
