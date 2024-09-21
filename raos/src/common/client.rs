use async_trait::async_trait;

#[derive(Debug, Default, Clone)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub confidential: bool,
    pub supports_openid_connect: bool,
}

impl Client {
    pub fn is_valid(&self) -> bool {
        if self.client_id.is_empty() {
            return false
        }
        if self.redirect_uris.is_empty() {
            return false
        }
        true
    }
}

#[cfg_attr(test, mockall::automock(type Error = ();))]
#[async_trait]
pub trait ClientProvider: 'static + Send + Sync {
    type Error;

    async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, Self::Error>;

    async fn allow_client_scopes(
        &self,
        client: &Client,
        scopes: Vec<String>,
    ) -> Result<Vec<String>, Self::Error>;

    async fn verify_client_secret(
        &self,
        client: &Client,
        client_secret: &str,
    ) -> Result<bool, Self::Error>;
}
