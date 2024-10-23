use crate::{
    authorize::GrantAuthorizationResult,
    common::{
        frontend::{FrontendResponse, FrontendResponseExt},
        model::Client,
    },
    test::{
        mock::request_from_raw_http, TestEnvironment, DEFAULT_AUTHORIZATION_CODE,
        DEFAULT_CLIENT_SECRET, DEFAULT_REDIRECT_URI,
    },
};
use mockall::predicate::always;

mod request;
mod response;
mod validate;

#[tokio::test]
async fn test_authorize_full_flow() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider
        .expect_authorize_grant()
        .with(always(), always(), always())
        .returning(|_, _, _| Ok(GrantAuthorizationResult::Authorized(1)));
    test.authorization_provider
        .expect_generate_code_for_grant()
        .with(always())
        .returning(|_| Ok(DEFAULT_AUTHORIZATION_CODE.to_string()));
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=client&redirect_uri=https://example.com/return&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let response = result.unwrap();
    assert_eq!(Ok(DEFAULT_AUTHORIZATION_CODE.to_string()), response.result);
    assert_eq!(DEFAULT_REDIRECT_URI, response.redirect_uri.to_string());
}

#[tokio::test]
async fn test_client_id_missing_produces_no_redirect() {
    // If the request fails due to a missing, invalid, or mismatching redirect URI,
    // or if the client identifier is missing or invalid,
    // the authorization server SHOULD inform the resource owner of the error
    // and MUST NOT automatically redirect the user agent to the invalid redirect URI.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?redirect_uri=https://example.com/return&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_client_id_invalid_produces_no_redirect() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.client_provider.expect_get_client_by_id().with(always()).returning(|_| Ok(None));
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=INVALID&redirect_uri=https://example.com/return&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_redirect_uri_missing_produces_no_redirect() {
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

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=client&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_redirect_uri_invalid_produces_no_redirect() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.register_client(
        Client { redirect_uris: vec!["❤".to_string()], ..Default::default() },
        DEFAULT_CLIENT_SECRET.to_string(),
    );
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=client&redirect_uri=❤&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_redirect_uri_mismatching_produces_no_redirect() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=client&redirect_uri=https://example.com/wrong&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_authorize_all_other_errors_are_redirect() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider.expect_authorize_grant().returning(|_, _, _| Err(()));
    let manager = test.build();

    let request = request_from_raw_http(
        r#"
        GET /authorize?client_id=client&redirect_uri=https://example.com/return&response_type=code&code_challenge=CODE_CHALLENGE&scope=SCOPE&state=STATE HTTP/1.1
    "#,
    );

    // Act
    let result = manager.handle_authorization_request(request, None).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Redirect { .. }),
        "response is not a redirect, response is {:?}",
        response
    );
}
