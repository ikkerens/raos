use mockall::mock;
use async_trait::async_trait;
use crate::{
    common::Client,
    token::{GrantType, RefreshGrant, Token, TokenProvider}
};

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
