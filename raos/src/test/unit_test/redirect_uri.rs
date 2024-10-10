use crate::{
    authorize::{AuthorizationRequest, ResponseType},
    test::mock::mocked_oauth_manager,
    common::{Client, CodeChallenge}
};
use mockall::predicate::eq;

#[tokio::test]
async fn test_redirect_uri_format() {
    // The redirect URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
    // The redirect URI MAY include an "application/x-www-form-urlencoded" formatted query component ([WHATWG.URL]).
    // The redirect URI MUST NOT include a fragment component.

    let test = |uri: &'static str| async {
        // Arrange
        let manager = mocked_oauth_manager(|client, _, _| {
            client.expect_get_client_by_id().with(eq("client")).returning(|_| {
                Ok(Some(Client {
                    client_id: "client".to_string(),
                    redirect_uris: vec![uri.to_string()],
                    confidential: false,
                    supports_openid_connect: false,
                }))
            });
            client.expect_allow_client_scopes().returning(|_, scopes| Ok(scopes));
        });
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "client".to_string(),
            code_challenge: CodeChallenge::None,
            has_openid_nonce: false,
            redirect_uri: Some(uri.to_string()),
            scope: Some("scope".to_string()),
            state: None,
        };

        // Act
        manager.validate_authorization_request(request).await
    };

    // Assert
    test("https://example.com").await.expect("https://example.com should pass");
    test("https://example.com/?some=value")
        .await
        .expect("https://example.com/?some=value should pass");
    test("https://example.com/?some^value=check")
        .await
        .expect("https://example.com/?some=value should pass");
    test("https://example.com/#fragment")
        .await
        .expect_err("https://example.com/#fragment should not pass (fragment)");
    test("/redirect").await.expect_err("/redirect should not pass (not absolute)");
    test("redirect").await.expect_err("redirect should not pass (not absolute)");
}
