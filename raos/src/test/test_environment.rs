use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    common::model::{Client, CodeChallenge, Grant},
    manager::OAuthManager,
    test::mock::{MockAuthorizationProvider, MockClientProvider, MockTokenProvider},
    token::{GrantType, RefreshGrant, RequestedGrantType, Token, TokenRequest},
};
use mockall::predicate::{always, eq};
use std::time::Instant;

pub(crate) struct TestEnvironment {
    pub(crate) client_provider: MockClientProvider,
    pub(crate) authorization_provider: MockAuthorizationProvider,
    pub(crate) token_provider: MockTokenProvider,
}

pub(crate) static DEFAULT_CLIENT_ID: &str = "client";
pub(crate) static DEFAULT_CLIENT_SECRET: &str = "client_secret";
pub(crate) static DEFAULT_REDIRECT_URI: &str = "https://example.com/return";
pub(crate) static DEFAULT_AUTHORIZATION_CODE: &str = "authorization_code";
pub(crate) static DEFAULT_TOKEN: &str = "token";
pub(crate) static DEFAULT_CODE_VERIFIER: &str = "code_verifier";
pub(crate) static DEFAULT_REFRESH_TOKEN: &str = "refresh_token";

impl TestEnvironment {
    pub(crate) fn new() -> Self {
        Self {
            client_provider: MockClientProvider::new(),
            authorization_provider: MockAuthorizationProvider::new(),
            token_provider: MockTokenProvider::new(),
        }
    }

    pub(crate) fn build(self) -> OAuthManager<u32, (), ()> {
        OAuthManager::builder()
            .client_provider(self.client_provider)
            .authorization_provider(self.authorization_provider)
            .token_provider(self.token_provider)
            .build()
    }

    pub(crate) fn default_client(&mut self) {
        self.register_client(Client::default(), DEFAULT_CLIENT_SECRET.to_string());
    }

    pub(crate) fn register_client(&mut self, client: Client, client_secret: String) {
        let client_id = client.client_id.clone();
        self.client_provider
            .expect_allow_client_scopes()
            .withf(move |c, _| c.client_id == client_id)
            .returning(move |_, scopes| Ok(scopes));

        let client_id = client.client_id.clone();
        self.client_provider
            .expect_verify_client_secret()
            .withf(move |c, _| c.client_id == client_id)
            .returning(move |_, secret| Ok(secret == client_secret));

        self.client_provider
            .expect_get_client_by_id()
            .with(eq(client.client_id.clone()))
            .returning(move |_| Ok(Some(client.clone())));
    }

    pub(crate) fn default_grant(&mut self) {
        self.register_grant(DEFAULT_AUTHORIZATION_CODE.to_string(), Grant::default());
    }

    pub(crate) fn register_grant(&mut self, code: String, grant: Grant<u32>) {
        self.token_provider
            .expect_token()
            .with(
                always(),
                eq(GrantType::AuthorizationCode {
                    resource_owner: grant.owner_id,
                    scope: grant.scope.clone(),
                }),
            )
            .returning(move |_, _| {
                Ok(Token {
                    token: DEFAULT_TOKEN.to_string(),
                    refresh_token: Some(DEFAULT_REFRESH_TOKEN.to_string()),
                    valid_until: Instant::now(),
                })
            });

        let refresh_grant_origin = grant.clone();
        self.token_provider
            .expect_exchange_refresh_token()
            .with(eq(DEFAULT_REFRESH_TOKEN.to_string()))
            .returning(move |_| {
                Ok(Some(RefreshGrant {
                    client_id: refresh_grant_origin.client_id.clone(),
                    resource_owner: refresh_grant_origin.owner_id,
                    scope: refresh_grant_origin.scope.clone(),
                }))
            });

        self.authorization_provider
            .expect_exchange_code_for_grant()
            .with(eq(code))
            .returning(move |_| Ok(Some(grant.clone())));
    }

    pub(crate) fn default_refresh_token(&mut self) {
        self.register_refresh_token(DEFAULT_REFRESH_TOKEN.to_string(), Grant::default());
    }

    pub(crate) fn register_refresh_token(&mut self, refresh_token: String, grant: Grant<u32>) {
        let exchange_grant = grant.clone();
        self.token_provider
            .expect_exchange_refresh_token()
            .with(eq(refresh_token.clone()))
            .returning(move |_| {
                Ok(Some(RefreshGrant {
                    client_id: exchange_grant.client_id.clone(),
                    resource_owner: exchange_grant.owner_id,
                    scope: exchange_grant.scope.clone(),
                }))
            });

        self.token_provider
            .expect_token()
            .with(
                always(),
                eq(GrantType::RefreshToken(RefreshGrant {
                    client_id: grant.client_id.clone(),
                    resource_owner: grant.owner_id,
                    scope: grant.scope.clone(),
                })),
            )
            .returning(move |_, _| {
                Ok(Token {
                    token: DEFAULT_TOKEN.to_string(),
                    refresh_token: Some(refresh_token.clone()),
                    valid_until: Instant::now(),
                })
            });
    }
}

impl Default for Client {
    fn default() -> Self {
        Self {
            client_id: DEFAULT_CLIENT_ID.to_string(),
            redirect_uris: vec![DEFAULT_REDIRECT_URI.to_string()],
            confidential: false,
        }
    }
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self {
            response_type: ResponseType::Code,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            code_challenge: CodeChallenge::Plain {
                code_challenge: DEFAULT_CODE_VERIFIER.to_string(),
            },
            redirect_uri: Some(DEFAULT_REDIRECT_URI.to_string()),
            scope: Some("scope".to_string()),
            state: None,
        }
    }
}

impl Default for TokenRequest {
    fn default() -> Self {
        Self {
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_secret: Some(DEFAULT_CLIENT_SECRET.to_string()),
            grant_type: RequestedGrantType::AuthorizationCode {
                code: DEFAULT_AUTHORIZATION_CODE.to_string(),
                code_verifier: DEFAULT_CODE_VERIFIER.to_string(),
            },
            redirect_uri: Some(DEFAULT_REDIRECT_URI.to_string()),
            scope: Some(vec!["scope".to_string()]),
        }
    }
}

impl Default for Grant<u32> {
    fn default() -> Self {
        Self {
            owner_id: 1,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            scope: vec!["scope".to_string()],
            redirect_uri: DEFAULT_REDIRECT_URI.parse().unwrap(),
            code_challenge: CodeChallenge::Plain {
                code_challenge: DEFAULT_CODE_VERIFIER.to_string(),
            },
        }
    }
}
