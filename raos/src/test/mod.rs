mod redirect_uri;

use crate::{
    authorize::MockAuthorizationProvider, builder::OAuthManagerBuilder, common::MockClientProvider,
    manager::OAuthManager, token::MockTokenProvider,
};

fn mocked_oauth_manager<F>(setup: F) -> OAuthManager<u32, ()>
where
    F: FnOnce(&mut MockClientProvider, &mut MockAuthorizationProvider, &mut MockTokenProvider),
{
    let mut client_provider = MockClientProvider::new();
    let mut authorization_provider = MockAuthorizationProvider::new();
    let mut token_provider = MockTokenProvider::new();

    setup(&mut client_provider, &mut authorization_provider, &mut token_provider);

    OAuthManagerBuilder::new()
        .client_provider(client_provider)
        .authorization_provider(authorization_provider)
        .token_provider(token_provider)
        .build()
}
