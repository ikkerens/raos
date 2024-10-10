use crate::{
    authorize::AuthorizationProvider,
    common::{Client, ClientProvider, CodeChallenge, Grant},
    manager::OAuthManager,
    token::{GrantType, RefreshGrant, Token, TokenProvider}
};
use async_trait::async_trait;
use std::{
    sync::LazyLock,
    string::ToString,
    time::{Duration, Instant}
};
use crate::authorize::AuthorizationResult;

static DOCTEST_CLIENT: LazyLock<Client> = LazyLock::new(|| Client {
    client_id: "CLIENT_ID".to_string(),
    redirect_uris: vec!["https://example.com".to_string()],
    ..Default::default()
});

/// Mock function to return a owner ID used in other tests
pub fn owner_id_from_session() -> u32 {
    1
}

/// Mock function to return a oauth manager with basic data
pub fn oauth_manager_from_application_state() -> OAuthManager<u32, ()> {
    OAuthManager::builder()
        .client_provider(DocTestClientProvider)
        .authorization_provider(DocTestAuthorizationProvider)
        .token_provider(DocTestTokenProvider)
        .build()
}

struct DocTestClientProvider;

#[async_trait]
impl ClientProvider for DocTestClientProvider {
    type Error = ();

    async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, Self::Error> {
        if client_id == DOCTEST_CLIENT.client_id {
            Ok(Some(DOCTEST_CLIENT.clone()))
        } else {
            Ok(None)
        }
    }

    async fn allow_client_scopes(&self, _client: &Client, scopes: Vec<String>) -> Result<Vec<String>, Self::Error> {
        Ok(scopes)
    }

    async fn verify_client_secret(&self, _client: &Client, client_secret: &str) -> Result<bool, Self::Error> {
        Ok(client_secret == "CLIENT_SECRET")
    }
}

struct DocTestAuthorizationProvider;

#[async_trait]
impl AuthorizationProvider for DocTestAuthorizationProvider {
    type OwnerId = u32;
    type Error = ();

    async fn authorize_grant(&self, _grant: &Grant<Self::OwnerId>) -> Result<AuthorizationResult, Self::Error> {
        Ok(AuthorizationResult::Authorized)
    }

    async fn generate_code_for_grant(&self, _grant: Grant<Self::OwnerId>) -> Result<String, Self::Error> {
        Ok("AUTHORIZATION_CODE".to_string())
    }

    async fn exchange_code_for_grant(&self, code: String) -> Result<Option<Grant<Self::OwnerId>>, Self::Error> {
        if code == "AUTHORIZATION_CODE" {
            Ok(Some(Grant {
                owner_id: 1,
                client_id: "CLIENT_ID".to_string(),
                scope: vec!["SCOPE".to_string()],
                redirect_uri: "https://example.com".parse().unwrap(),
                code_challenge: CodeChallenge::Plain {
                    code_challenge: "CODE_CHALLENGE".to_string(),
                },
            }))
        } else {
            Ok(None)
        }
    }
}

struct DocTestTokenProvider;

#[async_trait]
impl TokenProvider for DocTestTokenProvider {
    type OwnerId = u32;
    type Error = ();

    async fn token(
        &self,
        _client: &Client,
        _grant: GrantType<Self::OwnerId>,
    ) -> Result<Token, Self::Error> {
        Ok(Token {
            token: "ACCESS_TOKEN".to_string(),
            refresh_token: Some("REFRESH_TOKEN".to_string()),
            valid_until: Instant::now() + Duration::from_secs(3600),
        })
    }

    async fn exchange_refresh_token(
        &self,
        _client: &Client,
        _refresh_token: String,
    ) -> Result<Option<RefreshGrant<Self::OwnerId>>, Self::Error> {
        if _refresh_token == "REFRESH_TOKEN" {
            Ok(Some(RefreshGrant {
                resource_owner: 1,
                scope: vec!["SCOPE".to_string()],
            }))
        } else {
            Ok(None)
        }
    }
}
