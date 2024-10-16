use crate::{
    authorize::AuthorizationProvider,
    common::ClientProvider,
    manager::{OAuthConfig, OAuthManager},
    token::TokenProvider,
};

/// The OAuthManagerBuilder is used to build an [OAuthManager].
/// This builder is used to configure the OAuthManager with the necessary providers,
/// and to set the configuration options.
pub struct OAuthManagerBuilder<C, A, T> {
    client_provider: Option<C>,
    authorization_provider: Option<A>,
    token_provider: Option<T>,
    config: OAuthConfig,
}

impl OAuthManagerBuilder<NeedsClientProvider, NeedsAuthorizationProvider, NeedsTokenProvider> {
    pub(crate) fn new() -> Self {
        Self {
            client_provider: None,
            authorization_provider: None,
            token_provider: None,
            config: OAuthConfig::default(),
        }
    }
}

impl<A, T> OAuthManagerBuilder<NeedsClientProvider, A, T> {
    /// Set the client provider for the OAuthManager.
    /// The client provider is used to get information about clients that are making requests.
    /// See [ClientProvider] for more information.
    pub fn client_provider<C>(self, client_provider: C) -> OAuthManagerBuilder<C, A, T>
    where
        C: ClientProvider,
    {
        OAuthManagerBuilder {
            client_provider: Some(client_provider),
            authorization_provider: self.authorization_provider,
            token_provider: self.token_provider,
            config: self.config,
        }
    }
}

impl<C, T> OAuthManagerBuilder<C, NeedsAuthorizationProvider, T> {
    /// Set the authorization provider for the OAuthManager.
    /// The authorization provider is used to authorize grants and exchange codes for grants.
    /// See [AuthorizationProvider] for more information.
    pub fn authorization_provider<A>(
        self,
        authorization_provider: A,
    ) -> OAuthManagerBuilder<C, A, T>
    where
        A: AuthorizationProvider,
    {
        OAuthManagerBuilder {
            authorization_provider: Some(authorization_provider),
            client_provider: self.client_provider,
            token_provider: self.token_provider,
            config: self.config,
        }
    }
}

impl<C, A> OAuthManagerBuilder<C, A, NeedsTokenProvider> {
    /// Set the token provider for the OAuthManager.
    /// The token provider is used to generate and validate tokens and refresh tokens.
    /// See [TokenProvider] for more information.
    pub fn token_provider<T>(self, token_provider: T) -> OAuthManagerBuilder<C, A, T>
    where
        T: TokenProvider,
    {
        OAuthManagerBuilder {
            token_provider: Some(token_provider),
            client_provider: self.client_provider,
            authorization_provider: self.authorization_provider,
            config: self.config,
        }
    }
}

impl<C, A, T> OAuthManagerBuilder<C, A, T> {
    /// Calling require_code_challenge will change the code_challenge requirement from RECOMMENDED to REQUIRED, even for confidential clients.
    /// If this function is not called, the code challenge is not enforced if all the following criteria are met:
    /// - The client is marked as confidential. (Client.confidential is true)
    /// - The client correctly implements the OpenID Connect nonce. (Client.supports_openid_connect is true AND the request has a nonce)
    ///
    /// See more [link](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-11.html#section-7.5.2)
    pub fn require_code_challenge(mut self) -> Self {
        self.config.require_code_challenge = true;
        self
    }

    /// Calling disallow_plain_code_challenge will disallow the use of plain code challenges.
    /// If this function is called, the code challenge must be a S256 challenge.
    /// This is a security measure to prevent code injection attacks.
    pub fn disallow_plain_code_challenge(mut self) -> Self {
        self.config.disallow_plain_code_challenge = true;
        self
    }

    /// Set the authorization server identifier.
    /// This is used to identify the authorization server in the authorization response.
    /// This is an optional setting.
    pub fn set_authorization_server_identifier(mut self, identifier: String) -> Self {
        self.config.authorization_server_identifier = Some(identifier);
        self
    }
}

impl<C, A, T, O, E, Ex> OAuthManagerBuilder<C, A, T>
where
    C: ClientProvider<Error = E>,
    A: AuthorizationProvider<OwnerId = O, Error = E, Extras = Ex>,
    T: TokenProvider<OwnerId = O, Error = E>,
{
    /// Build the OAuthManager with the configured providers.
    /// This function will consume the builder and return an OAuthManager.
    pub fn build(self) -> OAuthManager<O, E, Ex> {
        OAuthManager {
            client_provider: Box::new(self.client_provider.unwrap()),
            authorization_provider: Box::new(self.authorization_provider.unwrap()),
            token_provider: Box::new(self.token_provider.unwrap()),
            config: self.config,
        }
    }
}

/// Marker type for the [OAuthManagerBuilder] to indicate that the client provider is needed,
/// it does not fulfill the trait requirements causing it to prevent the manager from being built.
pub struct NeedsClientProvider;
/// Marker type for the [OAuthManagerBuilder] to indicate that the authorization provider is needed,
/// it does not fulfill the trait requirements causing it to prevent the manager from being built.
pub struct NeedsAuthorizationProvider;
/// Marker type for the [OAuthManagerBuilder] to indicate that the token provider is needed,
/// it does not fulfill the trait requirements causing it to prevent the manager from being built.
pub struct NeedsTokenProvider;
