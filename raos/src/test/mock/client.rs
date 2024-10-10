use crate::common::{Client, ClientProvider};
use async_trait::async_trait;
use mockall::mock;

mock! {
    pub ClientProvider {}

    #[async_trait]
    impl ClientProvider for ClientProvider {
        type Error = ();
        async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, ()>;
        async fn allow_client_scopes(&self, client: &Client, scopes: Vec<String>) -> Result<Vec<String>, ()>;
        async fn verify_client_secret(&self, client: &Client, client_secret: &str) -> Result<bool, ()>;
    }
}
