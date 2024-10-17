use async_trait::async_trait;

/// Represents a OAuth client.
#[derive(Debug, Clone)]
pub struct Client {
    /// The client id.
    pub client_id: String,
    /// The known redirect uris the client is allowed to use.
    pub redirect_uris: Vec<String>,
    /// Marks the client as confidential.
    ///
    /// Confidential clients MUST authenticate with the authorization server, for example by using client credentials.
    pub confidential: bool,
    /// Whether this client is allowed to use openid connect features
    ///
    /// While this library does not have any inherent openid connect support, this option can be set
    /// to allow skipping the code challenge requirement for openid connect clients, as long as they include
    /// a nonce in the request.
    pub supports_openid_connect: bool,
}

impl Client {
    /// Checks if the client is valid.
    /// A client is valid if it has a non-empty client id and at least one redirect uri.
    pub fn is_valid(&self) -> bool {
        if self.client_id.is_empty() {
            return false;
        }
        if self.redirect_uris.is_empty() {
            return false;
        }
        true
    }
}

/// Client provider trait
/// This is one of the traits that has to be implemented by the end user, for the oauth manager to work.
///
/// This trait is used to help the library discover clients, verify the scopes a client is allowed to use and verify client secrets.
#[async_trait]
pub trait ClientProvider<Extras = ()>: 'static + Send + Sync {
    /// This is the error type that can be returned by the authorization provider implementing this trait.
    /// This type will need to match the Error used in [TokenProvider](crate::token::TokenProvider) and [AuthorizationProvider](crate::authorize::AuthorizationProvider).
    type Error;

    /// Get a client by its client id.
    ///
    /// # Implementation notes
    /// If the client secret is kept in the same location as client information, please ensure it does not get loaded in this function.
    /// Secret validation is handled in [ClientProvider::verify_client_secret] instead.
    ///
    /// # Arguments
    /// * `client_id` - The client id of the client to get.
    ///
    /// # Returns
    /// An [Option] containing the [Client] if it was found, or [None] if the client was not found.
    ///
    /// # Errors
    /// If the client provider fails to get the client, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>, Self::Error>;

    /// Check if a client is allowed to use a set of scopes.
    ///
    /// # Implementation notes
    /// Ownership of the scopes is transferred to the client provider, so a good practise is to
    /// convert it into an iterator and filter out the scopes the client is not allowed to use,
    /// returning the Vec returned with collect.
    ///
    /// # Arguments
    /// * `client` - The client to check the scopes for.
    /// * `scopes` - The scopes to check.
    ///
    /// # Returns
    /// A [Vec] containing the scopes that were in the original requested scopes, with all the scopes that the client is not allowed to use removed.
    ///
    /// # Errors
    /// If the client provider fails to check the scopes, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn allow_client_scopes(
        &self,
        client: &Client,
        scopes: Vec<String>,
    ) -> Result<Vec<String>, Self::Error>;

    /// Verify a client secret.
    ///
    /// # Implementation notes
    /// Please ensure that the client_secret is stored in a hashed form, and that the client_secret is hashed before comparing.
    /// Good algorithms for this are bcrypt, scrypt or argon2.
    /// If another format is used, please ensure it is compared in a constant time manner.
    ///
    /// # Arguments
    /// * `client` - The client to verify the secret for.
    /// * `client_secret` - The client secret to verify.
    ///
    /// # Returns
    /// A [bool] indicating if the client secret is valid.
    ///
    /// # Errors
    /// If the client provider fails to verify the client secret, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn verify_client_secret(
        &self,
        client: &Client,
        client_secret: &str,
    ) -> Result<bool, Self::Error>;
}

#[cfg(test)]
mod test {
    use crate::common::Client;

    #[test]
    fn test_client_is_valid() {
        let client = Client {
            client_id: "client_id".to_string(),
            redirect_uris: vec!["http://localhost".to_string()],
            confidential: false,
            supports_openid_connect: false,
        };

        assert!(client.is_valid());
    }

    #[test]
    fn test_client_with_multiple_redirect_uris_is_valid() {
        // The authorization server MAY allow the client to register multiple redirect URIs.
        let client = Client {
            client_id: "client_id".to_string(),
            redirect_uris: vec![
                "http://localhost".to_string(),
                "http://localhost:8080".to_string(),
            ],
            confidential: false,
            supports_openid_connect: false,
        };

        assert!(client.is_valid());
    }

    #[test]
    fn test_client_without_client_id_is_invalid() {
        let client = Client {
            client_id: "".to_string(),
            redirect_uris: vec!["http://localhost".to_string()],
            confidential: false,
            supports_openid_connect: false,
        };

        assert!(!client.is_valid());
    }

    #[test]
    fn test_client_without_redirect_uris_is_invalid() {
        let client = Client {
            client_id: "client_id".to_string(),
            redirect_uris: vec![],
            confidential: false,
            supports_openid_connect: false,
        };

        assert!(!client.is_valid());
    }
}
