pub use provider::*;
pub use request::*;
pub use response::*;
pub use validate::*;

use crate::{
    common::{
        frontend::{FrontendRequest, OAuthError},
        model::Grant,
    },
    manager::OAuthManager,
};
use std::mem::take;

mod provider;
mod request;
mod response;
#[cfg(test)]
mod test;
mod validate;

impl<U: 'static, E: 'static, Ex: 'static> OAuthManager<U, E, Ex> {
    /// Handle an incoming authorization request from a client.
    /// This function will parse the incoming request, validate it, and then authorize the request,
    /// returning an [AuthorizationResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The unparsed incoming request from the client, represented by a [FrontendRequest]
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
    /// let result = manager.handle_authorization_request(req, None).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_authorization_request(
        &self,
        req: impl FrontendRequest,
        extras: Option<Ex>,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Take the raw frontend request parameters, and convert it into an AuthorizationRequest
        let request = AuthorizationRequest::try_from(&req as &dyn FrontendRequest)?;
        self.handle_authorization(request, extras).await
    }

    /// Handle an incoming authorization request from a client.
    /// This function will validate the incoming request, and then authorize the request,
    /// returning an [AuthorizationResponse] that contains the information for the client to use.
    ///
    /// # Parameters
    /// - `req` - The parsed incoming request from the client, represented by an [AuthorizationRequest]
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
    /// #     common::model::CodeChallenge
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = AuthorizationRequest {
    ///     response_type: ResponseType::Code,
    ///     client_id: "CLIENT_ID".to_string(),
    ///     code_challenge: CodeChallenge::Plain {code_challenge: "CODE_CHALLENGE".to_string()},
    ///     redirect_uri: Some("https://example.com".to_string()),
    ///     scope: Some("SCOPE".to_string()),
    ///     state: Some("STATE".to_string()),
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.handle_authorization(req, None).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn handle_authorization(
        &self,
        req: AuthorizationRequest,
        extras: Option<Ex>,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Validate the input of the decoded request
        // We use the try operator to bubble up the response into the error response
        let mut validated = self.validate_authorization_request(req).await?;

        // Handle the authorization request
        // This error we handle manually, as we need to return a response to the client by redirecting
        let result = match self.handle_authorization_internal(&mut validated, extras).await {
            // Success path
            Ok(code) => Ok(code),
            // If we require a resource owner interaction, also bubble up normally
            Err(e @ OAuthError::RequiresResourceOwnerInteraction(_)) => return Err(e),
            // Any errors that don't pop up during early validation, we redirect back to the client
            Err(e) => Err(e.into()),
        };

        // Send back the response
        Ok(AuthorizationResponse {
            result,
            state: validated.state,
            iss: self.config.authorization_server_identifier.clone(),
            redirect_uri: validated.redirect_uri,
        })
    }

    async fn handle_authorization_internal(
        &self,
        validated: &mut ValidatedAuthorizationRequest,
        mut extras: Option<Ex>,
    ) -> Result<String, OAuthError<E>> {
        // Authorize the grant, by checking in with the authorization provider
        let authorization_result = self
            .authorization_provider
            .authorize_grant(&validated.client, &validated.scopes, &mut extras)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;

        let owner_id = match authorization_result {
            // If we are authorized, continue normally
            GrantAuthorizationResult::Authorized(owner_id) => owner_id,
            // If we require authentication, we need to return a response to the client.
            // We ask the authorization provider to make a response for us, which we then return.
            GrantAuthorizationResult::RequireAuthentication => {
                let response = self
                    .authorization_provider
                    .handle_required_authentication(&mut extras)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?;
                return Err(OAuthError::RequiresResourceOwnerInteraction(response));
            }
            // If we require scope consent, we need to return a response to the client.
            // We ask the authorization provider to make a response for us, which we then return.
            GrantAuthorizationResult::RequireScopeConsent(scope) => {
                let response = self
                    .authorization_provider
                    .handle_missing_scope_consent(scope, &mut extras)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?;
                return Err(OAuthError::RequiresResourceOwnerInteraction(response));
            }
            // If we are unauthorized, return an access denied error
            GrantAuthorizationResult::Unauthorized => return Err(OAuthError::AccessDenied),
        };

        // Create a grant from the validated request and the owner id from the granted request
        let grant = Grant {
            owner_id,
            // Redirect uri is needed in some error responses, so don't take it
            redirect_uri: validated.redirect_uri.clone(),
            // The remaining values are taken from the validated request
            client_id: take(&mut validated.client.client_id),
            scope: take(&mut validated.scopes),
            code_challenge: validated.code_challenge.take(),
        };

        // After validation, exchange our grant for an authorization code that can later be exchanged
        // for a token by the client.
        let code = self
            .authorization_provider
            .generate_code_for_grant(grant)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;

        Ok(code)
    }
}
