use std::marker::PhantomData;

use dashmap::DashMap;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use crate::authorize::AuthorizationResult;
use crate::{async_trait, authorize::AuthorizationProvider, common::Grant};

/// An in-memory authorization provider that stores the grants in a `DashMap`.
/// This is useful for testing purposes, or for applications that do not require persistent storage.
/// Please note, this authorization provider will approve consent for all grants.
pub struct InMemoryAuthorizationProvider<U, E> {
    codes: DashMap<String, Grant<U>>,
    _phantom: PhantomData<E>,
}

impl<U, E> Default for InMemoryAuthorizationProvider<U, E> {
    fn default() -> Self {
        Self { codes: DashMap::new(), _phantom: PhantomData }
    }
}

#[async_trait]
impl<U: 'static, E: 'static> AuthorizationProvider for InMemoryAuthorizationProvider<U, E>
where
    U: Send + Sync,
    E: Send + Sync,
{
    type OwnerId = U;
    type Error = E;

    async fn authorize_grant(
        &self,
        _grant: &Grant<Self::OwnerId>,
    ) -> Result<AuthorizationResult, Self::Error> {
        Ok(AuthorizationResult::Authorized)
    }

    async fn generate_code_for_grant(
        &self,
        grant: Grant<Self::OwnerId>,
    ) -> Result<String, Self::Error> {
        let random_string: String =
            thread_rng().sample_iter(&Alphanumeric).take(50).map(char::from).collect();

        self.codes.insert(random_string.clone(), grant);
        Ok(random_string)
    }

    async fn exchange_code_for_grant(
        &self,
        code: String,
    ) -> Result<Option<Grant<Self::OwnerId>>, Self::Error> {
        let grant = self.codes.remove(&code).map(|(_, g)| g);
        Ok(grant)
    }
}
