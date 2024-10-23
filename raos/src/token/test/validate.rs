use crate::{
    common::{
        frontend::{OAuthError, OAuthValidationError},
        model::{Client, CodeChallenge, Grant},
    },
    test::{
        TestEnvironment, DEFAULT_AUTHORIZATION_CODE, DEFAULT_CLIENT_SECRET, DEFAULT_CODE_VERIFIER,
        DEFAULT_REDIRECT_URI,
    },
    token::{RequestedGrantType, TokenRequest},
};

#[tokio::test]
async fn test_only_accept_code_challenge_if_originally_present() {
    // The authorization server MUST verify that the code_verifier parameter is present if and only if a code_challenge parameter was present in the authorization request.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { confidential: true, ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.register_grant(
        DEFAULT_AUTHORIZATION_CODE.to_string(),
        Grant { code_challenge: CodeChallenge::None, ..Default::default() },
    );
    let manager = test.build();

    let request = TokenRequest {
        grant_type: RequestedGrantType::AuthorizationCode {
            code: DEFAULT_AUTHORIZATION_CODE.to_string(),
            code_verifier: DEFAULT_CODE_VERIFIER.to_string(),
        },
        ..Default::default()
    };

    // Act
    let result = manager.validate_token_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidCodeVerifier),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_client_credentials_only_allowed_by_confidential_clients() {
    // The client credentials grant type MUST only be used by confidential clients.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client {
            client_id: "confidential_client".to_string(),
            confidential: true,
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.register_client(
        Client {
            client_id: "regular_client".to_string(),
            confidential: false,
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let confidential_request = TokenRequest {
        client_id: "confidential_client".to_string(),
        grant_type: RequestedGrantType::ClientCredentials,
        ..Default::default()
    };
    let regular_request = TokenRequest {
        client_id: "regular_client".to_string(),
        grant_type: RequestedGrantType::ClientCredentials,
        ..Default::default()
    };

    // Act
    let confidential_result = manager.validate_token_request(confidential_request).await;
    let regular_result = manager.validate_token_request(regular_request).await;

    // Assert
    assert!(confidential_result.is_ok(), "result is not Ok, result is {:?}", confidential_result);
    assert!(regular_result.is_err(), "result is not Err, result is {:?}", regular_result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::ClientNotAllowedToUseGrantType {
            requested: "client_credentials"
        }),
        regular_result.unwrap_err()
    );
}

#[tokio::test]
async fn test_authorization_code_belongs_to_authorized_client() {
    // The authorization server MUST ensure that the authorization code was issued to the authenticated confidential client,
    // or if the client is public, ensure that the code was issued to client_id in the request.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_client(
        Client { client_id: "bad_client".to_string(), ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_grant();
    let manager = test.build();

    let request = TokenRequest { client_id: "bad_client".to_string(), ..Default::default() };

    // Act
    let result = manager.validate_token_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::AuthorizationCodeClientMismatch),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_token_request_that_includes_redirect_uri_should_have_it_validated() {
    // For backwards compatibility of an authorization server wishing to support both OAuth 2.0 and OAuth 2.1 clients,
    // the authorization server MUST allow clients to send the redirect_uri parameter in the token request,
    // and MUST enforce the parameter.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.default_grant();
    let manager = test.build();

    let request = TokenRequest {
        redirect_uri: Some("https://example.com/wrong_uri".to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_token_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::UnknownRedirectUri),
        result.unwrap_err()
    );
}

#[tokio::test]
async fn test_token_request_that_includes_redirect_uri_should_be_the_same_as_the_original() {
    // For backwards compatibility of an authorization server wishing to support both OAuth 2.0 and OAuth 2.1 clients,
    // the authorization server MUST allow clients to send the redirect_uri parameter in the token request,
    // and MUST enforce the parameter.

    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client {
            redirect_uris: vec![
                DEFAULT_REDIRECT_URI.to_string(),
                "https://example.com/another".to_string(),
            ],
            ..Default::default()
        },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    test.default_grant(); // Uses DEFAULT_REDIRECT_URI
    let manager = test.build();

    let request = TokenRequest {
        redirect_uri: Some("https://example.com/another".to_string()),
        ..Default::default()
    };

    // Act
    let result = manager.validate_token_request(request).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthError::ValidationFailed(OAuthValidationError::InvalidRedirectUri),
        result.unwrap_err()
    );
}
