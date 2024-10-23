use crate::common::frontend::{FrontendResponse, FrontendResponseExt, OAuthError};
use crate::{
    authorize::{AuthorizationRequest, GrantAuthorizationResult},
    common::frontend::PublicOAuthError,
    test::TestEnvironment,
};

#[tokio::test]
async fn test_grant_denied() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider
        .expect_authorize_grant()
        .returning(|_, _, _| Ok(GrantAuthorizationResult::Unauthorized));
    let manager = test.build();

    let request = AuthorizationRequest::default();

    // Act
    let result = manager.handle_authorization(request, None).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    let response = result.unwrap();
    assert!(
        response.result.is_err(),
        "response.result is not Err, response.result is {:?}",
        response.result
    );
    assert_eq!(PublicOAuthError::AccessDenied, response.result.unwrap_err());
}

#[tokio::test]
async fn test_grant_requires_consent() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider
        .expect_authorize_grant()
        .returning(|_, scope, _| Ok(GrantAuthorizationResult::RequireScopeConsent(scope.to_vec())));
    test.authorization_provider
        .expect_handle_missing_scope_consent()
        .times(1)
        .returning(|_, _| Ok(OAuthError::<()>::AccessDenied.into_frontend_response()));
    let manager = test.build();

    let request = AuthorizationRequest::default();

    // Act
    let result = manager.handle_authorization(request, None).await;

    // Assert
    // We only test default behaviour
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}

#[tokio::test]
async fn test_grant_requires_authentication() {
    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.authorization_provider
        .expect_authorize_grant()
        .returning(|_, _, _| Ok(GrantAuthorizationResult::RequireAuthentication));
    test.authorization_provider
        .expect_handle_required_authentication()
        .times(1)
        .returning(|_| Ok(OAuthError::<()>::AccessDenied.into_frontend_response()));
    let manager = test.build();

    let request = AuthorizationRequest::default();

    // Act
    let result = manager.handle_authorization(request, None).await;

    // Assert
    // We only test default behaviour
    let response = result.into_frontend_response();
    assert!(
        matches!(response, FrontendResponse::Error { .. }),
        "response is not an error, response is {:?}",
        response
    );
}
