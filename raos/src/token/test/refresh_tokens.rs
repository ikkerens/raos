use crate::test::DEFAULT_TOKEN;
use crate::{
    common::{
        frontend::{OAuthError, OAuthValidationError},
        model::{Client, Grant},
    },
    test::{
        TestEnvironment, DEFAULT_AUTHORIZATION_CODE, DEFAULT_CLIENT_SECRET, DEFAULT_REFRESH_TOKEN,
    },
    token::{RequestedGrantType, TokenRequest},
};
use mockall::predicate::always;

#[tokio::test]
async fn test_refresh_token_enforce_same_scopes() {
    // If refresh tokens are issued, those refresh tokens MUST be bound to the scope and resource servers as consented by the resource owner.
    // When using the refresh_token, the requested scope MUST NOT include any scope not originally granted by the resource owner,
    // and if omitted is treated as equal to the scope originally granted by the resource owner.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_grant(
        DEFAULT_AUTHORIZATION_CODE.to_string(),
        Grant { scope: vec!["some".to_string(), "scopes".to_string()], ..Default::default() },
    );
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::RefreshToken {
            refresh_token: DEFAULT_REFRESH_TOKEN.to_string(),
        },
        scope: Some(vec!["some".to_string(), "wrong".to_string()]),
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::ScopeNotConsented),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_refresh_token_confidential_client_requires_authentication() {
    // When using the refresh_token, confidential clients must authenticate with the authorization server.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: true, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_refresh_token();
    let manager = test.build();

    let request = TokenRequest {
        client_secret: None,
        grant_type: RequestedGrantType::RefreshToken {
            refresh_token: DEFAULT_REFRESH_TOKEN.to_string(),
        },
        ..Default::default()
    };

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
async fn test_refresh_token_belongs_to_requesting_client() {
    // When using the refresh_token, the authorization server MUST verify that if client authentication is included in the request,
    // ensure that the refresh token was issued to the authenticated client,
    // OR if a client_id is included in the request, ensure the refresh token was issued to the matching client.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_client(
        Client { client_id: "bad_client".to_string(), ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_refresh_token();
    let manager = test.build();

    let request = TokenRequest {
        client_id: "bad_client".to_string(),
        grant_type: RequestedGrantType::RefreshToken {
            refresh_token: DEFAULT_REFRESH_TOKEN.to_string(),
        },
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::RefreshTokenClientMismatch),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_refresh_token_valid() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.default_refresh_token();
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::RefreshToken {
            refresh_token: DEFAULT_REFRESH_TOKEN.to_string(),
        },
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    assert_eq!(DEFAULT_TOKEN, result.unwrap().access_token);
}

#[tokio::test]
async fn test_refresh_token_invalid() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.default_refresh_token();
    test.token_provider.expect_exchange_refresh_token().with(always()).returning(|_| Ok(None));
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::RefreshToken { refresh_token: "wrong_token".to_string() },
        ..Default::default()
    };

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidRefreshToken),
        result.unwrap_err()
    );
}
