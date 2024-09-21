use serde::Serialize;
use url::Url;

use crate::common::{FrontendResponse, FrontendResponseExt, PublicOAuthError};

#[derive(Serialize)]
pub struct AuthorizationResponse {
    pub code: String,
    pub state: Option<String>,
    pub iss: Option<String>,

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
