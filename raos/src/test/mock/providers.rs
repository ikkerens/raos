use crate::{
    authorize::{AuthorizationProvider, AuthorizationResult},
    common::{Client, ClientProvider, FrontendResponse, Grant},
    token::{GrantType, RefreshGrant, Token, TokenProvider},
};
use async_trait::async_trait;
use mockall::mock;

mock! {
    pub AuthorizationProvider {}

    #[async_trait]
    impl AuthorizationProvider for AuthorizationProvider {
        type OwnerId = u32;
        type Extras = ();
        type Error = ();
        async fn authorize_grant(&self, grant: &Grant<u32>, extras: &mut Option<()>) -> Result<AuthorizationResult, ()>;
        async fn generate_code_for_grant(&self, grant: Grant<u32>) -> Result<String, ()>;
        async fn exchange_code_for_grant(&self, code: String) -> Result<Option<Grant<u32>>, ()>;
        async fn handle_required_authentication(&self, extras: &mut Option<()>) -> Result<FrontendResponse, ()>;
        async fn handle_missing_scope_consent(&self, scopes: Vec<String>, extras: &mut Option<()>) -> Result<FrontendResponse, ()>;
    }
}

mock! {
    pub ClientProvider {}

    #[async_trait]
    impl ClientProvider for ClientProvider {
        type Error = ();
        async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, ()>;
        async fn allow_client_scopes(&self, client: &Client, scopes: Vec<String>) -> Result<Vec<String>, ()>;
        async fn verify_client_secret(&self, client: &Client, client_secret: &str) -> Result<bool, ()>;
    }
}

mock! {
    pub TokenProvider {}

    #[async_trait]
    impl TokenProvider for TokenProvider {
        type OwnerId = u32;
        type Error = ();
        async fn token(&self, client: &Client, grant: GrantType<u32>) -> Result<Token, ()>;
        async fn exchange_refresh_token(&self, client: &Client, refresh_token: String) -> Result<Option<RefreshGrant<u32>>, ()>;
    }
}
