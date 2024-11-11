#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

//! # RAOS-axum
//!
//! ## In development
//!
//! **R**ust **A**sync **O**auth **S**erver
//! Axum wrapper for RAOS.

use axum::{async_trait, extract::Query, extract::{FromRequest, Request}, http::Method, http::StatusCode, Json, RequestExt};
use raos::common::frontend::{FrontendRequest, FrontendRequestMethod, PublicOAuthErrorBody};
use std::{
    cell::OnceCell,
    collections::HashMap,
};
use std::sync::LazyLock;
use axum::http::request::Parts;

pub struct AxumRequest {
    request: Parts,
    query: OnceCell<HashMap<String, String>>,
    body: LazyLock<HashMap<String, String>>,
}

#[async_trait]
impl<S> FromRequest<S> for AxumRequest
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<PublicOAuthErrorBody>);

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        Ok(Self {
            request: parts,
            query: OnceCell::new(),
            body: LazyLock::new(move || {
                Query::<HashMap<String, String>>::try_from(body)
                    .map(|q| q.0)
                    .unwrap_or_else(|_| HashMap::new())
            }),
        })
    }
}

impl FrontendRequest for AxumRequest {
    fn request_method(&self) -> FrontendRequestMethod {
        match &self.request.method {
            &Method::GET => FrontendRequestMethod::GET,
            &Method::POST => FrontendRequestMethod::POST,
            method => FrontendRequestMethod::OtherUnsupported(method.to_string()),
        }
    }

    fn header_param(&self, key: &str) -> Option<String> {
        self.request.headers.get(key).map(|v| v.to_str().unwrap().to_string())
    }

    fn query_param(&self, key: &str) -> Option<String> {
        let query = self.query.get_or_init(|| {
            Query::<HashMap<String, String>>::try_from_uri(&self.request.uri)
                .map(|q| q.0)
                .unwrap_or_else(|_| HashMap::new())
        });
        query.get(key).cloned()
    }

    fn body_param(&self, key: &str) -> Option<String> {
        self.body.get(key).cloned()
    }
}