use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    common::{Client, CodeChallenge},
    manager::OAuthManager,
    test::mock::{MockAuthorizationProvider, MockClientProvider, MockTokenProvider},
};
use mockall::predicate::eq;

pub(crate) struct TestEnvironment {
    client_provider: MockClientProvider,
    authorization_provider: MockAuthorizationProvider,
    token_provider: MockTokenProvider,
}

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
}

pub(crate) static DEFAULT_CLIENT_SECRET: &str = "client_secret";

impl Default for Client {
    fn default() -> Self {
        Self {
            client_id: "client".to_string(),
            redirect_uris: vec!["https://example.com/return".to_string()],
            confidential: false,
            supports_openid_connect: false,
        }
    }
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self {
            response_type: ResponseType::Code,
            client_id: "client".to_string(),
            code_challenge: CodeChallenge::None,
            has_openid_nonce: false,
            redirect_uri: Some("https://example.com/return".to_string()),
            scope: Some("scope".to_string()),
            state: None,
        }
    }
}
