use crate::{
    common::{
        frontend::{OAuthError, OAuthValidationError},
        model::Client,
    },
    manager::OAuthManager,
    token::{RefreshGrant, RequestedGrantType, TokenRequest},
};

/// A validated token request.
#[derive(Debug)]
pub struct ValidatedTokenRequest<OwnerId> {
    /// The client that is requesting the token.
    pub client: Client,
    /// The type of grant requested by the client.
    pub grant_type: GrantType<OwnerId>,
}

/// The type of grant requested by the client.
#[derive(Debug, PartialEq)]
pub enum GrantType<OwnerId> {
    /// The client is requesting an access token using client credentials.
    ClientCredentials,
    /// The client is requesting an access token using an authorization code.
    AuthorizationCode {
        /// The resource owner that authorized the code.
        resource_owner: OwnerId,
        /// The requested scope.
        scope: Vec<String>,
    },
    /// The client is requesting an access token using a refresh token.
    RefreshToken(RefreshGrant<OwnerId>),
}

impl<U: 'static, E: 'static, Ex: 'static> OAuthManager<U, E, Ex> {
    /// Validate an incoming token request from a client.
    /// This function will validate the incoming request, and then return a [ValidatedTokenRequest]
    /// that contains the information needed to generate the token.
    ///
    /// # Parameters
    /// - `req` - The parsed incoming request from the client, represented by a [TokenRequest]
    ///
    /// # Returns
    /// A [ValidatedTokenRequest] that contains the information needed to generate the token.
    ///
    /// # Errors
    /// This function can return an [OAuthError] if the request is invalid,
    /// or if the [TokenProvider](crate::token::TokenProvider), [AuthorizationProvider](crate::authorize::AuthorizationProvider)
    /// or the [ClientProvider](crate::common::ClientProvider) return an error.
    ///
    /// # Example
    /// ```
    /// # use raos::{
    /// #     test::doctest::oauth_manager_from_application_state,
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
    /// let result = manager.validate_token_request(req).await;
    /// assert!(result.is_ok());
    /// # });
    pub async fn validate_token_request(
        &self,
        req: TokenRequest,
    ) -> Result<ValidatedTokenRequest<U>, OAuthError<E>> {
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

        if let Some(client_secret) = req.client_secret {
            let secret_valid = self
                .client_provider
                .verify_client_secret(&client, &client_secret)
                .await
                .map_err(OAuthError::ProviderImplementationError)?;
            if !secret_valid {
                return Err(OAuthValidationError::InvalidClientSecret.into());
            }
        } else if client.confidential
            || !matches!(req.grant_type, RequestedGrantType::AuthorizationCode { .. })
        {
            return Err(OAuthValidationError::MissingRequiredParameter("client_secret").into());
        }

        if let Some(ref redirect_uri) = req.redirect_uri {
            if !client.has_redirect_uri(redirect_uri) {
                return Err(OAuthValidationError::UnknownRedirectUri.into());
            }
        }

        let grant_type = match req.grant_type {
            RequestedGrantType::ClientCredentials => {
                if !client.confidential {
                    return Err(OAuthValidationError::ClientNotAllowedToUseGrantType {
                        requested: "client_credentials",
                    }
                    .into());
                }
                GrantType::ClientCredentials
            }
            RequestedGrantType::RefreshToken { refresh_token } => {
                let Some(refresh_grant) = self
                    .token_provider
                    .exchange_refresh_token(refresh_token)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?
                else {
                    return Err(OAuthValidationError::InvalidRefreshToken.into());
                };

                if client.client_id != refresh_grant.client_id {
                    return Err(OAuthValidationError::RefreshTokenClientMismatch.into());
                }

                if let Some(scope) = &req.scope {
                    if scope.iter().filter(|scope| !refresh_grant.scope.contains(scope)).count() > 0
                    {
                        return Err(OAuthValidationError::ScopeNotConsented.into());
                    }
                }

                GrantType::RefreshToken(refresh_grant)
            }
            RequestedGrantType::AuthorizationCode { code, code_verifier } => {
                let Some(grant) = self
                    .authorization_provider
                    .exchange_code_for_grant(code)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?
                else {
                    return Err(OAuthValidationError::InvalidAuthorizationCode.into());
                };

                if !grant.code_challenge.verify(&code_verifier) {
                    return Err(OAuthValidationError::InvalidCodeVerifier.into());
                }
                if grant.client_id != client.client_id {
                    return Err(OAuthValidationError::AuthorizationCodeClientMismatch.into());
                }
                if let Some(redirect_uri) = req.redirect_uri {
                    if grant.redirect_uri.to_string() != redirect_uri {
                        return Err(OAuthValidationError::InvalidRedirectUri.into());
                    }
                }

                GrantType::AuthorizationCode { resource_owner: grant.owner_id, scope: grant.scope }
            }
        };

        Ok(ValidatedTokenRequest { client, grant_type })
    }
}
