use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Router
};
use example_support::{
    DumbTokenProvider, ExampleAuthorizationProvider, VecClient, VecClientProvider,
};
use raos::{common::model::Client, manager::OAuthManager};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let oauth = Arc::new(
        OAuthManager::builder()
            .client_provider(VecClientProvider(vec![VecClient {
                client: Client {
                    client_id: "test".to_string(),
                    redirect_uris: vec!["https://oauthdebugger.com/debug".to_string()],
                    confidential: false,
                },
                scopes: vec!["bla"],
                secret: "bla".to_string(),
            }]))
            .authorization_provider(ExampleAuthorizationProvider::default())
            .token_provider(DumbTokenProvider)
            .disallow_plain_code_challenge()
            .build()
    );

    let app = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn authorize(
    State(_oauth): State<Arc<OAuthManager<u32, (), ()>>>
) -> Result<String, (StatusCode, String)> {
    Ok("Hello, world!".to_string())
}