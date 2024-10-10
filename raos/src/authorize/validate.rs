use url::Url;

use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    common::{Client, CodeChallenge, OAuthError, OAuthValidationError},
    manager::OAuthManager,
};

/// A validated authorization request from a client.
/// This struct contains all the information needed to authorize a client's request.
/// This struct is produced by validating an [AuthorizationRequest] from a client.
#[derive(Debug)]
pub struct ValidatedAuthorizationRequest {
    /// The response type expected in the request.
    pub response_type: ResponseType,
    /// The client making the request, including all its information obtained from the [ClientProvider](crate::common::ClientProvider).
    pub client: Client,
    /// The code challenge and method used in the request.
    pub code_challenge: CodeChallenge,
    /// The redirect URI the client expects to be redirected to, or the only one the client has registered.
    pub redirect_uri: Url,
    /// The scopes requested by the client, after being filtered by the [ClientProvider](crate::common::ClientProvider).
    pub scopes: Vec<String>,
    /// The state of the request to be sent back to the client in the response.
    pub state: Option<String>,
}

impl<U: 'static, E: 'static> OAuthManager<U, E> {
    /// Validate an incoming authorization request from a client.
    /// This function will validate the incoming request, and then return a [ValidatedAuthorizationRequest]
    /// that contains the information needed to authorize the request.
    ///
    /// # Parameters
    /// - `req` - The parsed incoming request from the client, represented by an [AuthorizationRequest]
    ///
    /// # Returns
    /// A [ValidatedAuthorizationRequest] that contains the information needed to authorize the request.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid,
    /// or if the [AuthorizationProvider](crate::authorize::AuthorizationProvider) or [ClientProvider](crate::common::ClientProvider) return an error.
    /// 
    /// # Example
    /// ```
    /// # use raos::{
    /// #     test::doctest::oauth_manager_from_application_state,
    /// #     authorize::{AuthorizationRequest, ResponseType},
    /// #     common::CodeChallenge
    /// # };
    ///
    /// let manager = oauth_manager_from_application_state();
    /// let req = AuthorizationRequest {
    ///     response_type: ResponseType::Code,
    ///     client_id: "CLIENT_ID".to_string(),
    ///     code_challenge: CodeChallenge::Plain { code_challenge: "CODE_CHALLENGE".to_string() },
    ///     has_openid_nonce: false,
    ///     redirect_uri: Some("https://example.com".to_string()),
    ///     scope: Some("SCOPE".to_string()),
    ///     state: Some("STATE".to_string()),
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let result = manager.validate_authorization_request(req).await;
    /// assert!(result.is_ok());
    /// # });
    /// ```
    pub async fn validate_authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<ValidatedAuthorizationRequest, OAuthError<E>> {
        let Some(client) = self
            .client_provider
            .get_client_by_id(&req.client_id)
            .await
            .map_err(OAuthError::ProviderImplementationError)?
        else {
            return Err(OAuthValidationError::ClientDoesNotExist.into());
        };
        if !client.is_valid() {
            return Err(OAuthValidationError::InvalidClient.into());
        }

        let can_skip_challenge =
            client.confidential && client.supports_openid_connect && req.has_openid_nonce;
        if matches!(req.code_challenge, CodeChallenge::None)
            && (self.config.require_code_challenge && !can_skip_challenge)
        {
            return Err(OAuthValidationError::CodeChallengeRequired.into());
        }
        if self.config.disallow_plain_code_challenge
            && matches!(req.code_challenge, CodeChallenge::Plain { .. })
        {
            return Err(OAuthValidationError::CodeChallengeRequired.into());
        }

        let redirect_uri = if let Some(redirect_uri) = req.redirect_uri {
            if client.redirect_uris.contains(&redirect_uri) {
                redirect_uri
            } else {
                return Err(OAuthValidationError::UnknownRedirectUri.into());
            }
        } else if client.redirect_uris.len() == 1 {
            client
                .redirect_uris
                .first()
                .expect("Unexpected error: .first() is None after .len() == 1 check")
                .to_owned()
        } else {
            return Err(OAuthValidationError::NoRedirectUri.into());
        };
        let redirect_uri: Url =
            redirect_uri.parse().map_err(|_| OAuthValidationError::InvalidRedirectUri)?;
        if redirect_uri.fragment().is_some() {
            return Err(OAuthValidationError::InvalidRedirectUri.into());
        }

        let scopes = if let Some(scope) = req.scope {
            scope.split(' ').map(str::to_string).collect()
        } else {
            Vec::new()
        };
        let scopes = self
            .client_provider
            .allow_client_scopes(&client, scopes)
            .await
            .map_err(OAuthError::ProviderImplementationError)?;
        if scopes.is_empty() {
            return Err(OAuthValidationError::NoScopesProvided.into());
        }

        Ok(ValidatedAuthorizationRequest {
            response_type: req.response_type,
            client,
            code_challenge: req.code_challenge,
            redirect_uri,
            scopes,
            state: req.state,
        })
    }
}
