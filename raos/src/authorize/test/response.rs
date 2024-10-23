use crate::{
    authorize::AuthorizationResponse,
    common::frontend::{FrontendResponse, FrontendResponseExt},
};

#[test]
fn test_redirect_uri_query_is_preserved() {
    // The redirect URI MAY include an "application/x-www-form-urlencoded" formatted query component ([WHATWG.URL]), which MUST be retained when adding additional query parameters.

    // Arrange
    let request = AuthorizationResponse {
        result: Ok("code".to_string()),
        state: None,
        iss: None,
        redirect_uri: "https://example.com/return?some=value&other=value".parse().unwrap(),
    };

    // Act
    let result = request.into_frontend_response();

    // Assert
    let FrontendResponse::Redirect { location } = result else {
        panic!("FrontendResponse is not a redirect");
    };
    assert_eq!("https://example.com/return?some=value&other=value&code=code", location.to_string());
}
