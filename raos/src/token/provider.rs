use std::time::Instant;

use async_trait::async_trait;

use crate::{common::Client, token::GrantType};

/// Token provider trait.
/// This is one of the traits that has to be implemented by the end user, for the oauth manager to work.
/// 
/// This trait is used to generate tokens for clients and exchange refresh tokens for new tokens.
#[async_trait]
pub trait TokenProvider: 'static + Send + Sync {
    /// This is the type of the owner id that is used to identify the resource owner.
    /// This type will need to match the OwnerId used in [AuthorizationProvider](crate::authorize::AuthorizationProvider).
    type OwnerId;
    /// This is the error type that can be returned by the authorization provider implementing this trait.
    /// This type will need to match the Error used in [AuthorizationProvider](crate::authorize::AuthorizationProvider) and [ClientProvider](crate::common::ClientProvider).
    type Error;

    /// Generate a token for a client.
    /// 
    /// # Implementation notes
    /// It is recommended to ensure that the grant is fully recovered from the token, so that the token can be verified later.
    /// This can be done by either storing the grant in the token (e.g. JWT), or by storing the grant in a database and storing the id in the token.
    /// 
    /// # Arguments
    /// * `client` - The client to generate the token for.
    /// * `grant` - The grant to generate the token for.
    /// 
    /// # Returns
    /// A [Token] that contains the access token, a refresh token if this behaviour is supported and the instant at which the access token expires.
    /// 
    /// # Errors
    /// If the client is invalid, the grant is invalid or the token provider fails to generate the token, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn token(
        &self,
        client: &Client,
        grant: GrantType<Self::OwnerId>,
    ) -> Result<Token, Self::Error>;

    /// Exchange a refresh token for a new token.
    /// 
    /// # Implementation notes
    /// 
    /// # Arguments
    /// * `client` - The client to exchange the refresh token for.
    /// * `refresh_token` - The refresh token to exchange.
    /// 
    /// # Returns
    /// An [Option] containing the [RefreshGrant] if the refresh token was valid, or [None] if the refresh token was invalid.
    /// 
    /// # Errors
    /// If the client is invalid, the refresh token is invalid or the token provider fails to exchange the refresh token, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn exchange_refresh_token(
        &self,
        client: &Client,
        refresh_token: String,
    ) -> Result<Option<RefreshGrant<Self::OwnerId>>, Self::Error>;
}

/// A token returned by the [TokenProvider].
pub struct Token {
    /// The access token.
    pub token: String,
    /// The refresh token, if one should be sent back to the client.
    pub refresh_token: Option<String>,
    /// The instant at which the current access token expires.
    pub valid_until: Instant,
}

/// A refresh grant passed to the [TokenProvider] when exchanging a refresh token.
pub struct RefreshGrant<OwnerId> {
    /// The resource owner that authorized the refresh token.
    pub resource_owner: OwnerId,
    /// The requested scope.
    pub scope: Vec<String>,
}
