use raos::{
    async_trait,
    common::{Client, ClientProvider},
};

pub struct VecClient {
    pub client: Client,
    pub scopes: Vec<&'static str>,
    pub secret: String,
}

pub struct VecClientProvider(pub Vec<VecClient>);

impl VecClientProvider {
    fn get_vec_client_by_id(&self, client_id: &str) -> Option<&VecClient> {
        self.0.iter().find(|&c| c.client.client_id == client_id)
    }
}

#[async_trait]
impl ClientProvider for VecClientProvider {
    type Error = ();

    async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, Self::Error> {
        Ok(self.get_vec_client_by_id(client_id).map(|c| c.client.clone()))
    }

    async fn allow_client_scopes(
        &self,
        client: &Client,
        scopes: Vec<String>,
    ) -> Result<Vec<String>, Self::Error> {
        let Some(client) = self.get_vec_client_by_id(&client.client_id) else { return Err(()) };
        Ok(scopes.into_iter().filter(|s| client.scopes.contains(&s.as_str())).collect())
    }

    async fn verify_client_secret(
        &self,
        client: &Client,
        client_secret: &str,
    ) -> Result<bool, Self::Error> {
        let Some(client) = self.get_vec_client_by_id(&client.client_id) else { return Err(()) };
        Ok(client.secret == client_secret)
    }
}
