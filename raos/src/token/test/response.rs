use crate::{
    common::model::Grant,
    test::{TestEnvironment, DEFAULT_AUTHORIZATION_CODE},
    token::TokenRequest,
};

#[tokio::test]
async fn test_response_must_contain_identical_scope() {
    // The authorization server MUST include the scope response parameter in the token response to inform the client of the actual scope granted.

    // Arrange
    let mut test = TestEnvironment::new();
    test.default_client();
    test.register_grant(
        DEFAULT_AUTHORIZATION_CODE.to_string(),
        Grant { scope: vec!["some scope field".to_string()], ..Default::default() },
    );

    let request = TokenRequest::default();

    let manager = test.build();

    // Act
    let result = manager.handle_token(request).await;

    // Assert
    assert!(result.is_ok(), "result is not Ok, result is {:?}", result);
    assert_eq!("some scope field", result.unwrap().scope.unwrap());
}
