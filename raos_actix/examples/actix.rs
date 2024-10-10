use actix_web::{get, post, web, App, HttpServer};

use raos::{common::Client, manager::OAuthManager, util::InMemoryAuthorizationProvider};
use raos_actix::{ActixOAuthRequest, ActixOAuthResponse};
use example_support::{DumbTokenProvider, VecClient, VecClientProvider};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let oauth = web::Data::new(
        OAuthManager::builder()
            .client_provider(VecClientProvider(vec![VecClient {
                client: Client {
                    client_id: "test".to_string(),
                    redirect_uris: vec!["https://oauthdebugger.com/debug".to_string()],
                    ..Default::default()
                },
                scopes: vec!["bla"],
                secret: "bla".to_string(),
            }]))
            .authorization_provider(InMemoryAuthorizationProvider::default())
            .token_provider(DumbTokenProvider)
            .disallow_plain_code_challenge()
            .build(),
    );
    HttpServer::new(move || {
        App::new()
        .app_data(oauth.clone()) // Pass the oauth manager as data
        .service(authorize)
        .service(token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/authorize")]
async fn authorize(
    req: ActixOAuthRequest,
    oauth: web::Data<OAuthManager<u32, ()>>,
) -> ActixOAuthResponse {
    let result = oauth.handle_authorization_request(req, 15).await;
    if let Err(ref e) = result {
        println!("Error: {e:#?}");
    }
    result.into()
}

#[post("/token")]
async fn token(
    req: ActixOAuthRequest,
    oauth: web::Data<OAuthManager<u32, ()>>,
) -> ActixOAuthResponse {
    let result = oauth.handle_token_request(req).await;
    if let Err(ref e) = result {
        println!("Error: {e:#?}");
    }
    result.into()
}
