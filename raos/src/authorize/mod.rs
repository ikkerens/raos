pub use provider::*;
pub use request::*;
pub use response::*;
pub use validate::*;

use crate::{
    common::{FrontendRequest, Grant, OAuthError},
    manager::OAuthManager,
};

mod provider;
mod request;
mod response;
mod validate;

impl<U: 'static, E: 'static, Ex: 'static> OAuthManager<U, E, Ex> {
    /// Handle an incoming authorization request from a client.
    /// This function will parse the incoming request, validate it, and then authorize the request,
    /// returning an [AuthorizationResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The unparsed incoming request from the client, represented by a [FrontendRequest]
    /// - `owner_id` - The ID of the resource owner that is authorizing the request
    ///
    /// # Returns
    /// An [AuthorizationResponse] that can be used to build a response to the client, which in turn
    /// implements the [FrontendResponse] trait.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid, or if the authorization
    /// provider fails to authorize the request.
    ///
    /// # Example
    /// ```
    /// # use raos::test::{
    /// #     doctest::{oauth_manager_from_application_state, owner_id_from_session},
    /// #     mock::request_from_raw_http
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = request_from_raw_http(r#"
    ///     GET /authorize?client_id=CLIENT_ID&redirect_uri=https://example.com&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    /// "#);
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.handle_authorization_request(req, owner_id_from_session(), None).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_authorization_request(
        &self,
        req: impl FrontendRequest,
        owner_id: U,
        extras: Option<Ex>,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Take the raw frontend request parameters, and convert it into an AuthorizationRequest
        let request: AuthorizationRequest = (&req as &dyn FrontendRequest).try_into()?;
        self.handle_authorization(request, owner_id, extras).await
    }

    /// Handle an incoming authorization request from a client.
    /// This function will validate the incoming request, and then authorize the request,
    /// returning an [AuthorizationResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The parsed incoming request from the client, represented by an [AuthorizationRequest]
    /// - `owner_id` - The ID of the resource owner that is authorizing the request
    ///
    /// # Returns
    /// An [AuthorizationResponse] that can be used to build a response to the client, which in turn
    /// implements the [FrontendResponse] trait.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid, or if the authorization
    /// provider fails to authorize the request.
    ///
    /// # Example
    /// ```
    /// # use raos::{
    /// #     test::{
    /// #         doctest::{oauth_manager_from_application_state, owner_id_from_session},
    /// #         mock::request_from_raw_http,
    /// #     },
    /// #     authorize::{AuthorizationRequest, ResponseType},
    /// #     common::CodeChallenge
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = AuthorizationRequest {
    ///     response_type: ResponseType::Code,
    ///     client_id: "CLIENT_ID".to_string(),
    ///     code_challenge: CodeChallenge::Plain {code_challenge: "CODE_CHALLENGE".to_string()},
    ///     has_openid_nonce: false,
    ///     redirect_uri: Some("https://example.com".to_string()),
    ///     scope: Some("SCOPE".to_string()),
    ///     state: Some("STATE".to_string()),
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.handle_authorization(req, owner_id_from_session(), None).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_authorization(
        &self,
        req: AuthorizationRequest,
        owner_id: U,
        mut extras: Option<Ex>,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Validate the input of the decoded request, following spec rules & provider validation
        let validated = self.validate_authorization_request(req).await?;

        // Create a grant from the validated request
        let grant = Grant {
            owner_id,
            client_id: validated.client.client_id,
            scope: validated.scopes,
            redirect_uri: validated.redirect_uri.clone(),
            code_challenge: validated.code_challenge,
        };

        let authorization_result = self
            .authorization_provider
            .authorize_grant(&grant, &mut extras)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;
        match authorization_result {
            AuthorizationResult::Authorized => {} // Continue normally
            AuthorizationResult::RequireAuthentication => {
                let response = self
                    .authorization_provider
                    .handle_required_authentication(&mut extras)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?;
                return Err(OAuthError::RequiresResourceOwnerInteraction(response));
            }
            AuthorizationResult::RequireScopeConsent(scope) => {
                let response = self
                    .authorization_provider
                    .handle_missing_scope_consent(scope, &mut extras)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?;
                return Err(OAuthError::RequiresResourceOwnerInteraction(response));
            }
            AuthorizationResult::Unauthorized => return Err(OAuthError::AccessDenied),
        }

        // After validation, exchange our grant for an authorization code that can later be exchanged
        // for a token by the client.
        let code = self
            .authorization_provider
            .generate_code_for_grant(grant)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;

        Ok(AuthorizationResponse {
            code,
            state: validated.state,
            iss: self.config.authorization_server_identifier.clone(),
            redirect_uri: validated.redirect_uri,
        })
    }
}
