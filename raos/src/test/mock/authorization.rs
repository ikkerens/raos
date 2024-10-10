use crate::{
    authorize::{AuthorizationProvider, AuthorizationResult},
    common::Grant,
};
use async_trait::async_trait;
use mockall::mock;

mock! {
    pub AuthorizationProvider {}

    #[async_trait]
    impl AuthorizationProvider for AuthorizationProvider {
        type OwnerId = u32;
        type Error = ();

        async fn authorize_grant(&self, grant: &Grant<u32>) -> Result<AuthorizationResult, ()>;
        async fn generate_code_for_grant(&self, grant: Grant<u32>) -> Result<String, ()>;
        async fn exchange_code_for_grant(&self, code: String) -> Result<Option<Grant<u32>>, ()>;
    }
}
