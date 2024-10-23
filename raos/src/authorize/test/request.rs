use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    common::frontend::{FrontendRequest, OAuthValidationError},
    test::mock::request_from_raw_http,
};

#[test]
fn test_support_get_method_for_authorization_endpoint() {
    // The authorization server MUST support the use of the HTTP GET method for the authorization endpoint

    // Arrange
    let request = request_from_raw_http(
        r#"
            GET /authorize?client_id=1234&response_type=code HTTP/1.1
        "#,
    );

    // Act
    let result = AuthorizationRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!(ResponseType::Code, result.response_type);
    assert_eq!("1234", result.client_id);
}

#[test]
fn test_support_post_method_for_authorization_endpoint() {
    // The authorization server MAY support the POST method as well for the authorization endpoint
    // In this test we however use mixed origins for the variables, some as query param, some as request body

    // Arrange
    let request = request_from_raw_http(
        r#"
            POST /authorize?response_type=code HTTP/1.1

            client_id=1234
        "#,
    );

    // Act
    let result = AuthorizationRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!(ResponseType::Code, result.response_type);
    assert_eq!("1234", result.client_id);
}

#[test]
fn test_ignore_unrecognised_request_parameters() {
    // The authorization server MUST ignore unrecognized request parameters sent to the authorization endpoint.

    // Arrange
    let request = request_from_raw_http(
        r#"
            GET /authorize?client_id=1234&response_type=code&unrecognised=param HTTP/1.1
        "#,
    );

    // Act
    let result = AuthorizationRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
}

#[test]
fn test_request_with_empty_values_must_be_omitted() {
    // Parameters sent without a value MUST be treated as if they were omitted from the request.

    // Arrange
    let request = request_from_raw_http(
        r#"
            POST /authorize?client_id=&state= HTTP/1.1

            client_id=1234&response_type=code&scope=
        "#,
    );

    // Act
    let result = AuthorizationRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let result = result.unwrap();
    assert_eq!("1234", result.client_id);
    assert_eq!(None, result.state);
    assert_eq!(None, result.scope);
}

#[test]
fn test_request_with_invalid_state() {
    // The authorization server and client MUST sanitize (and validate when possible) any value received -- in particular, the value of the state and redirect_uri parameters.

    // Arrange
    let request = request_from_raw_http(
        r#"
            GET /authorize?client_id=1234&response_type=code&state=❤ HTTP/1.1
        "#,
    );

    // Act
    let result = AuthorizationRequest::try_from(&request as &dyn FrontendRequest);

    // Assert
    assert!(result.is_err(), "result is not Err, result is {:?}", result);
    assert_eq!(
        OAuthValidationError::InvalidParameterSyntax("state", "[!-~]+".to_string()),
        result.unwrap_err()
    );
}

#[test]
fn test_authorization_request_with_invalid_or_missing_response_type() {
    // If an authorization request is missing the response_type parameter, or if the response type is not understood, the authorization server MUST return an error response.

    // Arrange
    let request_missing = request_from_raw_http(
        r#"
            GET /authorize?client_id=1234 HTTP/1.1
        "#,
    );
    let request_invalid = request_from_raw_http(
        r#"
            GET /authorize?client_id=1234&response_type=bogus HTTP/1.1
        "#,
    );

    // Act
    let result_missing = AuthorizationRequest::try_from(&request_missing as &dyn FrontendRequest);
    let result_invalid = AuthorizationRequest::try_from(&request_invalid as &dyn FrontendRequest);

    // Assert
    assert!(result_missing.is_err(), "result is not Err, result is {:?}", result_missing);
    assert_eq!(
        OAuthValidationError::MissingRequiredParameter("response_type"),
        result_missing.unwrap_err()
    );
    assert!(result_invalid.is_err(), "result is not Err, result is {:?}", result_invalid);
    assert_eq!(
        OAuthValidationError::InvalidParameterValue("response_type", "bogus".to_string()),
        result_invalid.unwrap_err()
    );
}
