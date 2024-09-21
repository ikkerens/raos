use std::time::Instant;

use async_trait::async_trait;

use crate::{common::Client, token::GrantType};

#[cfg_attr(test, mockall::automock(type OwnerId = u32; type Error = ();))]
#[async_trait]
pub trait TokenProvider: 'static + Send + Sync {
    type OwnerId;
    type Error;

    async fn token(
        &self,
        client: &Client,
        grant: GrantType<Self::OwnerId>,
    ) -> Result<Token, Self::Error>;

    async fn exchange_refresh_token(
        &self,
        client: &Client,
        refresh_token: String,
    ) -> Result<Option<RefreshGrant<Self::OwnerId>>, Self::Error>;
}

pub struct Token {
    pub token: String,
    pub refresh_token: Option<String>,
    pub valid_until: Instant,
}

pub struct RefreshGrant<OwnerId> {
    pub resource_owner: OwnerId,
    pub scope: Vec<String>,
}
