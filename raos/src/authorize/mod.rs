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

impl<U: 'static, E: 'static> OAuthManager<U, E> {
    pub async fn handle_authorization_request(
        &self,
        req: impl FrontendRequest,
        owner_id: U,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Take the raw frontend request parameters, and convert it into an AuthorizationRequest
        let request: AuthorizationRequest = (&req as &dyn FrontendRequest).try_into()?;
        self.handle_authorization(request, owner_id).await
    }

    pub async fn handle_authorization(
        &self,
        req: AuthorizationRequest,
        owner_id: U,
    ) -> Result<AuthorizationResponse, OAuthError<E>> {
        // Validate the input of the decoded request, following spec rules & provider validation
        let validated = self.validate_authorization_request(req).await?;

        // TODO Add an AuthorizationProvider function to verify the resource owner's consent

        // Create a grant from the validated request
        let grant = Grant {
            owner_id,
            client_id: validated.client.client_id,
            scope: validated.scopes,
            redirect_uri: validated.redirect_uri.clone(),
            code_challenge: validated.code_challenge,g
        };

        // After validation, exchange our grant for an authorization code that can later be exchanged
        // for a token by the client.
        let code = self
            .authorization_provider
            .authorize_grant(grant)
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
