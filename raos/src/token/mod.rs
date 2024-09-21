pub use provider::*;
pub use request::*;
pub use response::*;
use std::time::Instant;
pub use validate::*;

use crate::{
    common::{FrontendRequest, OAuthError},
    manager::OAuthManager,
};

mod provider;
mod request;
mod response;
mod validate;

impl<U: 'static, E: 'static> OAuthManager<U, E> {
    pub async fn handle_token_request(
        &self,
        req: impl FrontendRequest,
    ) -> Result<TokenResponse, OAuthError<E>> {
        // Take the raw frontend request parameters, and convert it into an AuthorizationRequest
        let request: TokenRequest = (&req as &dyn FrontendRequest).try_into()?;
        self.handle_token(request).await
    }

    pub async fn handle_token(&self, req: TokenRequest) -> Result<TokenResponse, OAuthError<E>> {
        // Validate the input of the decoded request, following spec rules & provider validation
        let validated = self.validate_token_request(req).await?;

        let scope = match &validated.grant_type {
            GrantType::AuthorizationCode { scope, .. } | GrantType::RefreshToken { scope, .. } => {
                Some(scope.join(" "))
            }
            GrantType::ClientCredentials => None,
        };

        let token = self
            .token_provider
            .token(&validated.client, validated.grant_type)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;

        Ok(TokenResponse {
            access_token: token.token,
            token_type: "Bearer".to_string(),
            expires_in: token.valid_until.duration_since(Instant::now()).as_secs(),
            refresh_token: token.refresh_token,
            scope,
        })
    }
}
