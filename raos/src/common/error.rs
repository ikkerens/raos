use std::fmt::Debug;

use serde::Serialize;
use thiserror::Error;

use crate::common::FrontendRequestMethod;

#[derive(Error, Debug)]
pub enum OAuthValidationError {
    #[error("Missing required parameter: {0}")]
    MissingRequiredParameter(&'static str),
    #[error("Invalid parameter value for parameter {0}: {1}")]
    InvalidParameterValue(&'static str, String),
    #[error("Invalid request method: expected {expected:#?}, got {actual:#?}")]
    InvalidRequestMethod { expected: FrontendRequestMethod, actual: FrontendRequestMethod },
    #[error("Client (id) does not exist")]
    ClientDoesNotExist,
    #[error("The client credentials provided in the request and header mismatch")]
    MismatchedClientCredentials,
    #[error("The client returned from the provider is invalid.")]
    InvalidClient,
    #[error("The client secret is incorrect.")]
    InvalidClientSecret,
    #[error("A code challenge was required, but not offered.")]
    CodeChallengeRequired,
    #[error("No redirect uri was specified through either the request, nor the client")]
    NoRedirectUri,
    #[error("Redirect uri was passed, which was not listed in the client redirect_uris")]
    UnknownRedirectUri,
    #[error("Redirect uri could not be parsed, or contained a #fragment")]
    InvalidRedirectUri,
    #[error("No scopes were provided through either the request, nor the client provider (as a default)")]
    NoScopesProvided,
    #[error("The requested scope was not allowed by the client")]
    ScopeNotAllowed,
    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,
    #[error("Invalid refresh token")]
    InvalidRefreshToken,
    #[error("Invalid code verifier")]
    InvalidCodeVerifier,
}

#[derive(Error, Debug)]
pub enum OAuthError<E> {
    #[error("OAuth validation failed: {0}")]
    ValidationFailed(OAuthValidationError),
    #[error("Provider implementation error: {0}")]
    ProviderImplementationError(E),
}

#[derive(Error, Debug)]
pub enum PublicOAuthError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("invalid_client")]
    InvalidClient,
    #[error("server_error")]
    ServerError,
}

impl<E> From<OAuthError<E>> for PublicOAuthError {
    fn from(value: OAuthError<E>) -> Self {
        match value {
            OAuthError::ValidationFailed(
                OAuthValidationError::ClientDoesNotExist
                | OAuthValidationError::MismatchedClientCredentials
                | OAuthValidationError::InvalidClient
                | OAuthValidationError::InvalidClientSecret,
            ) => Self::InvalidClient,
            OAuthError::ValidationFailed(
                OAuthValidationError::ScopeNotAllowed | OAuthValidationError::NoScopesProvided,
            ) => Self::InvalidScope,
            OAuthError::ValidationFailed(_) => Self::InvalidRequest,
            OAuthError::ProviderImplementationError(_) => Self::ServerError,
        }
    }
}

impl<E> From<OAuthValidationError> for OAuthError<E> {
    fn from(value: OAuthValidationError) -> Self {
        Self::ValidationFailed(value)
    }
}

impl PublicOAuthError {
    pub fn to_description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
            Self::InvalidScope => "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
            Self::InvalidClient => "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
            Self::ServerError => "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        }
    }
}

#[derive(Serialize)]
pub struct PublicOAuthErrorBody {
    pub error: String,
    pub error_description: String,
}

impl From<PublicOAuthError> for PublicOAuthErrorBody {
    fn from(value: PublicOAuthError) -> Self {
        Self { error: format!("{value}"), error_description: value.to_description().to_string() }
    }
}
