use crate::{
    common::{Client, OAuthError, OAuthValidationError},
    manager::OAuthManager,
    token::{RequestedGrantType, TokenRequest},
};

pub struct ValidatedTokenRequest<OwnerId> {
    pub client: Client,
    pub grant_type: GrantType<OwnerId>,
}

pub enum GrantType<OwnerId> {
    ClientCredentials,
    AuthorizationCode { resource_owner: OwnerId, scope: Vec<String> },
    RefreshToken { resource_owner: OwnerId, scope: Vec<String> },
}

impl<U: 'static, E: 'static> OAuthManager<U, E> {
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

        // TODO Can this be prettier?
        match req.client_secret {
            Some(client_secret) => {
                let secret_valid = self
                    .client_provider
                    .verify_client_secret(&client, &client_secret)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?;
                if !secret_valid {
                    return Err(OAuthValidationError::InvalidClientSecret.into());
                }
            }
            None => {
                if client.confidential
                    || !matches!(req.grant_type, RequestedGrantType::AuthorizationCode { .. })
                {
                    return Err(
                        OAuthValidationError::MissingRequiredParameter("client_secret").into()
                    );
                }
            }
        }

        let grant_type = match req.grant_type {
            RequestedGrantType::ClientCredentials => GrantType::ClientCredentials,
            RequestedGrantType::RefreshToken { refresh_token } => {
                let Some(refresh_grant) = self
                    .token_provider
                    .exchange_refresh_token(&client, refresh_token)
                    .await
                    .map_err(OAuthError::ProviderImplementationError)?
                else {
                    return Err(OAuthValidationError::InvalidRefreshToken.into());
                };

                if let Some(scope) = &req.scope {
                    if scope.iter().filter(|scope| refresh_grant.scope.contains(scope)).count() > 0
                    {
                        return Err(OAuthValidationError::ScopeNotAllowed.into());
                    }
                }

                GrantType::RefreshToken {
                    resource_owner: refresh_grant.resource_owner,
                    scope: refresh_grant.scope,
                }
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

                // TODO Verify redirect_uri in token request?

                if !grant.code_challenge.verify(&code_verifier) {
                    return Err(OAuthValidationError::InvalidCodeVerifier.into());
                }

                GrantType::AuthorizationCode { resource_owner: grant.owner_id, scope: grant.scope }
            }
        };

        Ok(ValidatedTokenRequest { client, grant_type })
    }
}
