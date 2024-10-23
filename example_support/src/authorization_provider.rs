use std::collections::HashMap;

use rand::{distributions::Alphanumeric, thread_rng, Rng};
use raos::{
    async_trait,
    authorize::{AuthorizationProvider, GrantAuthorizationResult},
    common::model::{Client, Grant},
};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct ExampleAuthorizationProvider {
    codes: Mutex<HashMap<String, Grant<u32>>>,
}

#[async_trait]
impl AuthorizationProvider for ExampleAuthorizationProvider {
    type OwnerId = u32;
    type Extras = ();
    type Error = ();

    async fn authorize_grant(
        &self,
        _client: &Client,
        _scopes: &[String],
        _extras: &mut Option<Self::Extras>,
    ) -> Result<GrantAuthorizationResult<Self::OwnerId>, Self::Error> {
        // Authorize the grant for user id 1
        Ok(GrantAuthorizationResult::Authorized(1))
    }

    async fn generate_code_for_grant(
        &self,
        grant: Grant<Self::OwnerId>,
    ) -> Result<String, Self::Error> {
        let random_string: String =
            thread_rng().sample_iter(&Alphanumeric).take(50).map(char::from).collect();

        self.codes.lock().await.insert(random_string.clone(), grant);
        Ok(random_string)
    }

    async fn exchange_code_for_grant(
        &self,
        code: String,
    ) -> Result<Option<Grant<Self::OwnerId>>, Self::Error> {
        let grant = self.codes.lock().await.remove(&code);
        Ok(grant)
    }
}
