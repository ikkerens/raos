use crate::{
    authorize::AuthorizationProvider,
    builder::{
        NeedsAuthorizationProvider, NeedsClientProvider, NeedsTokenProvider, OAuthManagerBuilder,
    },
    common::ClientProvider,
    token::TokenProvider,
};

#[allow(dead_code)]
pub struct OAuthManager<OwnerIdType, ErrorType> {
    pub(crate) client_provider: Box<dyn ClientProvider<Error = ErrorType>>,
    pub(crate) authorization_provider:
        Box<dyn AuthorizationProvider<OwnerId = OwnerIdType, Error = ErrorType>>,
    pub(crate) token_provider: Box<dyn TokenProvider<OwnerId = OwnerIdType, Error = ErrorType>>,
    pub(crate) config: OAuthConfig,
}

impl OAuthManager<(), ()> {
    pub fn builder(
    ) -> OAuthManagerBuilder<NeedsClientProvider, NeedsAuthorizationProvider, NeedsTokenProvider>
    {
        OAuthManagerBuilder::new()
    }
}

#[derive(Default)]
pub(crate) struct OAuthConfig {
    pub(crate) require_code_challenge: bool,
    pub(crate) disallow_plain_code_challenge: bool,
    pub(crate) authorization_server_identifier: Option<String>,
}
