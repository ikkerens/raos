use std::{collections::HashMap, convert::Infallible};

use actix_web::{
    body::BoxBody, dev::Payload, http::Method, web, FromRequest, HttpRequest, HttpResponse,
    Responder,
};
use futures::{future::LocalBoxFuture, FutureExt};

use raos::common::{FrontendRequest, FrontendRequestMethod, FrontendResponse, FrontendResponseExt};

pub struct ActixOAuthRequest {
    method: FrontendRequestMethod,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: HashMap<String, String>,
}

impl ActixOAuthRequest {
    async fn new(req: HttpRequest, mut payload: Payload) -> Result<Self, Infallible> {
        let method = match req.method() {
            &Method::GET => FrontendRequestMethod::GET,
            &Method::POST => FrontendRequestMethod::POST,
            method => FrontendRequestMethod::OtherUnsupported(method.to_string()),
        };
        let headers = req
            .headers()
            .into_iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        let query = web::Query::<HashMap<String, String>>::extract(&req)
            .await
            .map(|s| s.0)
            .unwrap_or_default();
        let body = web::Form::<HashMap<String, String>>::from_request(&req, &mut payload)
            .await
            .map(|s| s.0)
            .unwrap_or_default();
        Ok(Self { method, headers, query, body })
    }
}

impl FromRequest for ActixOAuthRequest {
    type Error = Infallible;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        Self::new(req.clone(), payload.take()).boxed_local()
    }
}

impl FrontendRequest for ActixOAuthRequest {
    fn request_method(&self) -> FrontendRequestMethod {
        self.method.clone()
    }

    fn header_param(&self, key: &str) -> Option<String> {
        self.headers.get(key).cloned()
    }

    fn query_param(&self, key: &str) -> Option<String> {
        self.query.get(key).cloned()
    }

    fn body_param(&self, key: &str) -> Option<String> {
        self.body.get(key).cloned()
    }
}

pub struct ActixOAuthResponse {
    req: FrontendResponse,
}

impl<E> From<E> for ActixOAuthResponse
where
    E: FrontendResponseExt + Sized,
{
    fn from(value: E) -> Self {
        Self { req: value.into_frontend_response() }
    }
}

impl Responder for ActixOAuthResponse {
    type Body = BoxBody;

    fn respond_to(self, _: &HttpRequest) -> HttpResponse<Self::Body> {
        match self.req {
            FrontendResponse::Success { json } => HttpResponse::Ok().json(json),
            FrontendResponse::Error { error } => HttpResponse::BadRequest().json(error),
            FrontendResponse::Redirect { location } => {
                HttpResponse::Found().append_header(("Location", location.to_string())).finish()
            }
        }
    }
}
