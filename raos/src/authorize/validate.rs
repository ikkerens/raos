use url::Url;

use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    common::{Client, CodeChallenge, OAuthError, OAuthValidationError},
    manager::OAuthManager,
};

#[derive(Debug)]
pub struct ValidatedAuthorizationRequest {
    pub response_type: ResponseType,
    pub client: Client,
    pub code_challenge: CodeChallenge,
    pub redirect_uri: Url,
    pub scopes: Vec<String>,
    pub state: Option<String>,
}

impl<U: 'static, E: 'static> OAuthManager<U, E> {
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
