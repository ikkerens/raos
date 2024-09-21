use std::time::{Duration, Instant};

use rand::{distributions::Alphanumeric, thread_rng, Rng};

use raos::{
    async_trait,
    common::Client,
    token::{GrantType, RefreshGrant, Token, TokenProvider},
};

pub struct DumbTokenProvider;

#[async_trait]
impl TokenProvider for DumbTokenProvider {
    type OwnerId = u32;
    type Error = ();

    async fn token(
        &self,
        _client: &Client,
        _grant: GrantType<Self::OwnerId>,
    ) -> Result<Token, Self::Error> {
        let random_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50) // You can change this value as per your maximum length requirement.
            .map(char::from)
            .collect();
        Ok(Token {
            token: random_string,
            refresh_token: None,
            valid_until: Instant::now() + Duration::from_secs(3600),
        })
    }

    async fn exchange_refresh_token(
        &self,
        _client: &Client,
        _refresh_token: String,
    ) -> Result<Option<RefreshGrant<Self::OwnerId>>, Self::Error> {
        Ok(None)
    }
}
