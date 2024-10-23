use crate::{
    common::frontend::{FrontendRequest, FrontendRequestMethod, OAuthValidationError},
    test::mock::request_from_raw_http,
    token::TokenRequest,
};

// The authorization server MUST ignore unrecognized request parameters sent to the token endpoint.
#[test]
fn test_ignore_unrecognised_request_parameters() {
    // The authorization server MUST ignore unrecognized request parameters sent to the authorization endpoint.

    // Arrange
    let request = request_from_raw_http(
        r#"
            POST /token HTTP/1.1
            Content-Type: application/x-www-form-urlencoded

            client_id=1234&grant_type=authorization_code&code=AUTHORIZATION_CODE&code_verifier=CODE_CHALLENGE&unrecognised=parameter
        "#,
    );

    // Act
    let result = TokenRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
}

#[test]
fn test_token_endpoint_must_use_post() {
    // The client MUST use the HTTP POST method when making requests to the token endpoint.

    // Arrange
    let request = request_from_raw_http(
        r#"
            GET /token?client_id=1234&grant_type=authorization_code&code=AUTHORIZATION_CODE&code_verifier=CODE_CHALLENGE HTTP/1.1
        "#,
    );

    // Act
    let result = TokenRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthValidationError::InvalidRequestMethod {
            expected: FrontendRequestMethod::POST,
            actual: FrontendRequestMethod::GET,
        },
        result.unwrap_err()
    );
}

#[test]
fn test_endpoint_supports_client_credentials_in_body() {
    // To support clients in possession of a client secret, the authorization server MUST support the client including the client credentials in the request body.

    // Arrange
    let request = request_from_raw_http(
        r#"
            POST /token HTTP/1.1
            Content-Type: application/x-www-form-urlencoded

            client_id=1234&client_secret=5678&grant_type=client_credentials
        "#,
    );

    // Act
    let result = TokenRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!("1234", result.client_id);
    assert_eq!(Some("5678".to_string()), result.client_secret);
}

#[test]
fn test_request_with_empty_values_must_be_omitted() {
    // Parameters sent without a value MUST be treated as if they were omitted from the request.

    // Arrange
    let request = request_from_raw_http(
        r#"
            POST /token HTTP/1.1
            Content-Type: application/x-www-form-urlencoded

            client_id=&client_secret=&grant_type=client_credentials
        "#,
    );

    // Act
    let result = TokenRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(OAuthValidationError::MissingRequiredParameter("client_id"), result.unwrap_err());
}
