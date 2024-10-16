use crate::{
    authorize::{AuthorizationProvider, AuthorizationResult},
    common::{FrontendResponse, Grant},
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
