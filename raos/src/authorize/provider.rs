use async_trait::async_trait;

use crate::common::Grant;

#[cfg_attr(test, mockall::automock(type OwnerId = u32; type Error = ();))]
#[async_trait]
pub trait AuthorizationProvider: 'static + Send + Sync {
    type OwnerId;
    type Error;

    async fn authorize_grant(&self, grant: Grant<Self::OwnerId>) -> Result<String, Self::Error>;

    async fn exchange_code_for_grant(
        &self,
        code: String,
    ) -> Result<Option<Grant<Self::OwnerId>>, Self::Error>;
}
