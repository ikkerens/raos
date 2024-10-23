mod refresh_tokens;
mod request;
mod response;
mod validate;

use crate::{
    common::{
        frontend::{OAuthError, OAuthValidationError},
        model::{Client, CodeChallenge, Grant},
    },
    test::{
        TestEnvironment, DEFAULT_AUTHORIZATION_CODE, DEFAULT_CLIENT_SECRET, DEFAULT_CODE_VERIFIER,
        DEFAULT_TOKEN,
    },
    token::{RequestedGrantType, Token, TokenRequest},
};
use std::time::Instant;

#[tokio::test]
async fn test_token_full_flow() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.default_grant();
    let manager = test.build();

    let request = TokenRequest::default();

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!(DEFAULT_TOKEN, result.access_token);
}

#[tokio::test]
async fn test_token_full_flow_with_s256() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_grant(
        DEFAULT_AUTHORIZATION_CODE.to_string(),
        Grant {
            code_challenge: CodeChallenge::S256 {
                code_challenge: "jwf_hjmVE1z34-qKjaH_PDNofyjfJAMpPx_nLP0CRiI".to_string(),
            },
            ..Default::default()
        },
    );
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::AuthorizationCode {
            code: DEFAULT_AUTHORIZATION_CODE.to_string(),
            code_verifier: "h2NzVb9nyqWVp7fbg8LGjW8lbzSuZjrZBE7HHGYitcd".to_string(),
        },
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!(DEFAULT_TOKEN, result.access_token);
}

#[tokio::test]
async fn test_authorization_code_invalid() {
    // The authorization server MUST verify that the authorization code is valid.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider.expect_exchange_code_for_grant().returning(|code| {
        if code == "valid_code" {
            Ok(Some(Grant::default()))
        } else {
            Ok(None)
        }
    });
    test.token_provider.expect_token().times(1).returning(|_, _| {
        Ok(Token { token: "".to_string(), refresh_token: None, valid_until: Instant::now() })
    });
    let manager = test.build();

    let request_valid = TokenRequest {
        grant_type: RequestedGrantType::AuthorizationCode {
            code: "valid_code".to_string(),
            code_verifier: DEFAULT_CODE_VERIFIER.to_string(),
        },
        ..Default::default()
    };
    let request_invalid = TokenRequest {
        grant_type: RequestedGrantType::AuthorizationCode {
            code: "invalid_code".to_string(),
            code_verifier: DEFAULT_CODE_VERIFIER.to_string(),
        },
        ..Default::default()
    };

    // Act
    let result_valid = manager.handle_token(request_valid).await;
    let result_invalid = manager.handle_token(request_invalid).await;

    // Assert
    assert!(result_valid.is_ok(), "result is not Ok, result is {:?}", result_valid);
    assert!(result_invalid.is_err(), "result is not Err, result is {:?}", result_invalid);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidAuthorizationCode),
        result_invalid.unwrap_err()
    );
}

#[tokio::test]
async fn test_confidential_clients_must_use_authentication() {
    // The authorization server MUST require client authentication for confidential clients (or clients with other authentication requirements).

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: true, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_grant();
    let manager = test.build();

    let request = TokenRequest { client_secret: None, ..Default::default() };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::MissingRequiredParameter(
            "client_secret"
        )),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_nonconfidential_clients_may_skip_credentials() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: false, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_grant();
    let manager = test.build();

    let request = TokenRequest { client_secret: None, ..Default::default() };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
}

#[tokio::test]
async fn test_included_challenge_must_be_verified() {
    // The authorization server MUST associate the code_challenge and code_challenge_method values with the issued authorization code so the code challenge can be verified later.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_grant(
        DEFAULT_AUTHORIZATION_CODE.to_string(),
        Grant {
            code_challenge: CodeChallenge::Plain { code_challenge: "challenge".to_string() },
            ..Default::default()
        },
    );
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::AuthorizationCode {
            code: DEFAULT_AUTHORIZATION_CODE.to_string(),
            code_verifier: "".to_string(),
        },
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidCodeVerifier),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_server_verifies_client_credentials_if_included() {
    // The authorization server MUST authenticate the client if client authentication is included.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(Client::default(), "correct_password".to_string());
    test.default_grant();
    let manager = test.build();

    let request =
        TokenRequest { client_secret: Some("wrong_password".to_string()), ..Default::default() };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidClientSecret),
        result.unwrap_err()
    );
}
