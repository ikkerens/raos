pub use provider::*;
pub use request::*;
pub use response::*;
pub use validate::*;

use crate::{
    common::frontend::{FrontendRequest, OAuthError},
    manager::OAuthManager,
};
use std::time::Instant;

mod provider;
mod request;
mod response;
#[cfg(test)]
mod test;
mod validate;

impl<U: 'static, E: 'static, Ex: 'static> OAuthManager<U, E, Ex> {
    /// Handle an incoming token request from a client.
    /// This function will parse the incoming request, validate it, and then generate a token,
    /// returning a [TokenResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The unparsed incoming request from the client, represented by a [FrontendRequest]
    ///
    /// # Returns
    /// A [TokenResponse] that can be used to build a response to the client, which in turn
    /// implements the [FrontendResponse] trait.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid, or if the token
    /// provider fails to generate the token.
    ///
    /// # Example
    /// ```
    /// # use raos::test::{
    /// #    doctest::oauth_manager_from_application_state,
    /// #    mock::request_from_raw_http
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = request_from_raw_http(r#"
    ///     POST /token HTTP/1.1
    ///     Content-Type: application/x-www-form-urlencoded
    ///
    ///     grant_type=authorization_code&code=AUTHORIZATION_CODE&code_verifier=CODE_CHALLENGE&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
    /// "#);
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.handle_token_request(req).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_token_request(
        &self,
        req: impl FrontendRequest,
    ) -> Result<TokenResponse, OAuthError<E>> {
        // Take the raw frontend request parameters, and convert it into an AuthorizationRequest
        let request = TokenRequest::try_from(&req as &dyn FrontendRequest)?;
        self.handle_token(request).await
    }

    /// Handle an incoming token request from a client.
    /// This function will validate it, and then generate a token,
    /// returning a [TokenResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The parsed incoming request from the client, represented by a [TokenRequest]
    ///
    /// # Returns
    /// A [TokenResponse] that can be used to build a response to the client, which in turn
    /// implements the [FrontendResponse] trait.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid, or if the token
    /// provider fails to generate the token.
    ///
    /// # Example
    /// ```
    /// # use raos::{
    /// #     test::{
    /// #         doctest::oauth_manager_from_application_state,
    /// #         mock::request_from_raw_http
    /// #     },
    /// #     token::{RequestedGrantType, TokenRequest}
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = TokenRequest {
    ///     client_id: "CLIENT_ID".to_string(),
    ///     client_secret: Some("CLIENT_SECRET".to_string()),
    ///     grant_type: RequestedGrantType::AuthorizationCode {
    ///         code: "AUTHORIZATION_CODE".to_string(),
    ///         code_verifier: "CODE_CHALLENGE".to_string(),
    ///     },
    ///     redirect_uri: None, // OAuth 2.0 compatibility, not required in OAuth v2.1
    ///     scope: None
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.handle_token(req).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_token(&self, req: TokenRequest) -> Result<TokenResponse, OAuthError<E>> {
        // Validate the input of the decoded request, following spec rules & provider validation
        let validated = self.validate_token_request(req).await?;

        let scope = match &validated.grant_type {
            GrantType::AuthorizationCode { scope, .. }
            | GrantType::RefreshToken(RefreshGrant { scope, .. }) => Some(scope.join(" ")),
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
