use crate::{
    authorize::AuthorizationProvider,
    builder::{
        NeedsAuthorizationProvider, NeedsClientProvider, NeedsTokenProvider, OAuthManagerBuilder,
    },
    common::ClientProvider,
    token::TokenProvider,
};

/// The OAuthManager is the main struct that is used to interact with the OAuth2.1 server.
/// It can be used to authorize requests, exchange codes for grants, and validate tokens.
///
/// The OAuthManager is created through the [OAuthManagerBuilder](OAuthManagerBuilder) which can be obtained with the [OAuthManager::builder](OAuthManager::builder) function.
pub struct OAuthManager<OwnerIdType, ErrorType, Extras> {
    pub(crate) client_provider: Box<dyn ClientProvider<Error = ErrorType>>,
    pub(crate) authorization_provider:
        Box<dyn AuthorizationProvider<OwnerId = OwnerIdType, Error = ErrorType, Extras = Extras>>,
    pub(crate) token_provider: Box<dyn TokenProvider<OwnerId = OwnerIdType, Error = ErrorType>>,
    pub(crate) config: OAuthConfig,
}

impl OAuthManager<(), (), ()> {
    /// Create a new OAuthManagerBuilder to build an OAuthManager.
    /// This function is the entry point to create an OAuthManager.
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
