use std::fmt::Debug;

use serde::Serialize;
use thiserror::Error;

use crate::common::frontend::{FrontendRequestMethod, FrontendResponse, FrontendResponseExt};

/// The collection of errors that can happen during OAuth validation, excluding provider errors.
#[derive(Error, Debug, PartialEq)]
pub enum OAuthValidationError {
    /// A required parameter was missing from the request.
    #[error("Missing required parameter: {0}")]
    MissingRequiredParameter(&'static str),
    /// The request contained an invalid parameter syntax.
    #[error("Invalid parameter syntax for parameter {0}, should match regex {1}")]
    InvalidParameterSyntax(&'static str, String),
    /// An invalid parameter was passed to the request, that does not fit other error types.
    #[error("Invalid parameter value for parameter {0}: {1}")]
    InvalidParameterValue(&'static str, String),
    /// The request method was not expected.
    #[error("Invalid request method: expected {expected:#?}, got {actual:#?}")]
    InvalidRequestMethod {
        /// The expected request method.
        expected: FrontendRequestMethod,
        /// The actual request method.
        actual: FrontendRequestMethod,
    },
    /// The client (id) does not exist.
    #[error("Client (id) does not exist")]
    ClientDoesNotExist,
    /// The client credentials provided in the request and header mismatch.
    #[error("The client credentials provided in the request and header mismatch")]
    MismatchedClientCredentials,
    /// The client returned from the provider is invalid.
    #[error("The client returned from the provider is invalid.")]
    InvalidClient,
    /// The authenticated client is not authorized to use this authorization grant type.
    #[error("The authenticated client is not authorized to use this authorization grant type.")]
    ClientNotAllowedToUseGrantType {
        /// The requested grant type
        requested: &'static str,
    },
    /// The client secret provided by the request is incorrect.
    #[error("The client secret is incorrect.")]
    InvalidClientSecret,
    /// The code challenge method was plain, but plain code challenges are disallowed.
    #[error("A code challenge was required, but not offered.")]
    CodeChallengeRequired,
    /// The redirect uri was not provided in the request, nor was it the only one registered by the client.
    #[error("No redirect uri was specified through either the request, nor the client")]
    NoRedirectUri,
    /// The redirect uri was passed, which was not listed in the client redirect_uris.
    #[error("Redirect uri was passed, which was not listed in the client redirect_uris")]
    UnknownRedirectUri,
    /// The redirect uri could not be parsed, or contained a #fragment.
    #[error("Redirect uri could not be parsed, or contained a #fragment")]
    InvalidRedirectUri,
    /// No scopes were provided through either the request, nor the client provider (as a default).
    #[error("No scopes were provided through either the request, nor the client provider (as a default)"
    )]
    NoScopesProvided,
    /// The requested scope was not allowed by the resource owner.
    #[error("The requested scope was not allowed by the resource owner")]
    ScopeNotConsented,
    /// Invalid authorization code.
    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,
    /// Authorization code was not issued to this client
    #[error("Authorization code was not issued to this client")]
    AuthorizationCodeClientMismatch,
    /// Invalid refresh token.
    #[error("Invalid refresh token")]
    InvalidRefreshToken,
    /// Refresh token was not issued to this client
    #[error("Refresh token was not issued to this client")]
    RefreshTokenClientMismatch,
    /// Invalid code verifier.
    #[error("Invalid code verifier")]
    InvalidCodeVerifier,
}

/// The error type used to return from all OAuth functions, which splits into validation and provider errors.
#[derive(Error, Debug, PartialEq)]
pub enum OAuthError<E> {
    /// The request was denied access by the authorization provider or resource owner.
    #[error("Access denied")]
    AccessDenied,
    /// The request requires resource owner interaction, such as authentication or scope consent.
    #[error("Required scope consent")]
    RequiresResourceOwnerInteraction(FrontendResponse),
    /// An error occurred during OAuth validation, these are usually errors returned from the library.
    #[error("OAuth validation failed: {0}")]
    ValidationFailed(OAuthValidationError),
    /// An error occurred during the provider implementation, these are usually errors returned from the configured providers.
    #[error("Provider implementation error: {0}")]
    ProviderImplementationError(E),
}

impl<E> From<OAuthValidationError> for OAuthError<E> {
    fn from(value: OAuthValidationError) -> Self {
        Self::ValidationFailed(value)
    }
}

impl<E> FrontendResponseExt for OAuthError<E> {
    fn into_frontend_response(self) -> FrontendResponse {
        if let OAuthError::RequiresResourceOwnerInteraction(response) = self {
            return response;
        }

        let error: PublicOAuthError = self.into();
        FrontendResponse::Error { error: error.into() }
    }
}

/// The public OAuth error types that can be returned to the client.
/// These are the errors that are safe to show to the client, and do not expose any internal information.
#[derive(Error, Debug, PartialEq, Serialize)]
pub enum PublicOAuthError {
    /// The resource owner or authorization server denied the request.
    #[error("access_denied")]
    AccessDenied,
    /// The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
    #[error("invalid_request")]
    InvalidRequest,
    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
    #[error("invalid_scope")]
    InvalidScope,
    /// Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
    #[error("invalid_client")]
    InvalidClient,
    /// The authenticated client is not authorized to use this authorization grant type.
    #[error("unauthorized_client")]
    UnauthorizedClient,
    /// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
    #[error("server_error")]
    ServerError,
}

impl<E> From<OAuthError<E>> for PublicOAuthError {
    fn from(value: OAuthError<E>) -> Self {
        match value {
            OAuthError::AccessDenied => Self::AccessDenied,
            OAuthError::ValidationFailed(
                OAuthValidationError::ClientDoesNotExist
                | OAuthValidationError::MismatchedClientCredentials
                | OAuthValidationError::InvalidClient
                | OAuthValidationError::InvalidClientSecret,
            ) => Self::InvalidClient,
            OAuthError::ValidationFailed(
                OAuthValidationError::ScopeNotConsented | OAuthValidationError::NoScopesProvided,
            ) => Self::InvalidScope,
            OAuthError::ValidationFailed(
                OAuthValidationError::ClientNotAllowedToUseGrantType { .. },
            ) => Self::UnauthorizedClient,
            OAuthError::ValidationFailed(_) => Self::InvalidRequest,
            OAuthError::ProviderImplementationError(_) => Self::ServerError,
            OAuthError::RequiresResourceOwnerInteraction(_) => {
                // This should never happen, as this error is only used internally.
                Self::AccessDenied
            }
        }
    }
}

impl PublicOAuthError {
    /// Get a human-readable description of the error.
    /// This is used to generate the error_description field in the OAuth response.
    /// This is a static string, and does not contain any internal information.
    /// This is safe to show to the client.
    pub fn to_description(&self) -> &'static str {
        match self {
            Self::AccessDenied => "The resource owner or authorization server denied the request.",
            Self::InvalidRequest => "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
            Self::InvalidScope => "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
            Self::InvalidClient => "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
            Self::UnauthorizedClient => "The authenticated client is not authorized to use this authorization grant type.",
            Self::ServerError => "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        }
    }
}

/// The body of a public OAuth error response.
/// This struct is serialized into JSON to be sent back to the client.
#[derive(Debug, Serialize, PartialEq)]
pub struct PublicOAuthErrorBody {
    /// The error code to be sent back to the client.
    pub error: String,
    /// The human-readable description of the error.
    pub error_description: String,
}

impl From<PublicOAuthError> for PublicOAuthErrorBody {
    fn from(value: PublicOAuthError) -> Self {
        Self { error: format!("{value}"), error_description: value.to_description().to_owned() }
    }
}
