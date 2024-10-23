use crate::{
    authorize::AuthorizationRequest,
    common::{
        frontend::{OAuthError, OAuthValidationError},
        model::{Client, CodeChallenge},
    },
    test::{TestEnvironment, DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET, DEFAULT_REDIRECT_URI},
};

#[tokio::test]
async fn test_valid_url_pass() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { redirect_uris: vec![DEFAULT_REDIRECT_URI.to_string()], ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = AuthorizationRequest {
        redirect_uri: Some(DEFAULT_REDIRECT_URI.to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    assert_eq!(DEFAULT_REDIRECT_URI, result.unwrap().redirect_uri.to_string());
}

#[tokio::test]
async fn test_valid_url_with_query_pass() {
    // The redirect URI MAY include an "application/x-www-form-urlencoded" formatted query component ([WHATWG.URL]).

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client {
            redirect_uris: vec!["https://example.com/return?some=value&other=value".to_string()],
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = AuthorizationRequest {
        redirect_uri: Some("https://example.com/return?some=value&other=value".to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    assert_eq!(
        "https://example.com/return?some=value&other=value",
        result.unwrap().redirect_uri.to_string()
    );
}

#[tokio::test]
async fn test_invalid_url_fail() {
    // The redirect URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { redirect_uris: vec!["not_a_url".to_string()], ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request =
        AuthorizationRequest { redirect_uri: Some("not_a_url".to_string()), ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_mismatching_url_fail() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { redirect_uris: vec![DEFAULT_REDIRECT_URI.to_string()], ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = AuthorizationRequest {
        redirect_uri: Some("https://example.com/other".to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::UnknownRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_url_with_fragment_fail() {
    // The redirect URI MUST NOT include a fragment component.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client {
            redirect_uris: vec!["https://example.com/return#fragment".to_string()],
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = AuthorizationRequest {
        redirect_uri: Some("https://example.com/return#fragment".to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_client_with_multiple_redirect_uris_should_specify_redirect_uri() {
    // If multiple redirect URIs have been registered to a client, the client MUST include a redirect URI with the authorization request using the redirect_uri request parameter.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client {
            redirect_uris: vec![
                DEFAULT_REDIRECT_URI.to_string(),
                "https://example.com/other".to_string(),
            ],
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = AuthorizationRequest { redirect_uri: None, ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::NoRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_authorization_without_default_scope_should_fail() {
    // If the client omits the scope parameter when requesting authorization,
    // the authorization server MUST either process the request using a pre-defined default value
    // or fail the request indicating an invalid scope.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    let manager = test.build();

    let request = AuthorizationRequest { scope: None, ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::NoScopesProvided),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_authorization_with_default_scope_should_succeed() {
    // See test_authorization_without_default_scope_should_fail for the requirement.

    // Arrange
    let mut test = TestEnvironment::new();

    // Add a mocked implementation of the client provider that adds a default scope.
    test.client_provider
        .expect_allow_client_scopes()
        .withf(move |c, _| c.client_id == DEFAULT_CLIENT_ID)
        .returning(move |_, mut scopes| {
            scopes.append(&mut vec!["default_scope".to_string()]);
            Ok(scopes)
        });
    test.default_client();

    let manager = test.build();

    let request = AuthorizationRequest { scope: None, ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    assert_eq!("default_scope", result.unwrap().scopes.join(" "));
}

#[tokio::test]
async fn test_request_with_invalid_redirect_uri() {
    // The authorization server and client MUST sanitize (and validate when possible) any value received -- in particular, the value of the state and redirect_uri parameters.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { redirect_uris: vec!["❤".to_string()], ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request =
        AuthorizationRequest { redirect_uri: Some("❤".to_string()), ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_non_confidential_clients_must_use_code_challenge_verifier() {
    // If the client is not confidential, the authorization server MUST enforce the code_challenge and code_verifier parameters.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: false, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request =
        AuthorizationRequest { code_challenge: CodeChallenge::None, ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::CodeChallengeRequired),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_code_challenge_required_for_public_clients() {
    // An AS MUST reject requests without a code_challenge from public clients,
    // and MUST reject such requests from other clients unless there is reasonable assurance that the client mitigates authorization code injection in other ways.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: false, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request =
        AuthorizationRequest { code_challenge: CodeChallenge::None, ..Default::default() };

    // Act
    let result = manager.validate_authorization_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::CodeChallengeRequired),
        result.unwrap_err()
    );
}
