#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! # RAOS
//!
//! ## In development
//!
//! **R**ust **A**sync **O**auth **S**erver
//! A rust-based oauth2.1 server library,
//! that strictly follows [the draft](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-11.html)
//! (draft-ietf-oauth-v2-1-11) at time of writing.

pub use async_trait::async_trait;

/// The authorization module handles the authorization code flow.
pub mod authorize;
/// The builder module contains the builder for the manager.
pub mod builder;
/// The common module contains common types used throughout the library.
pub mod common;
/// The manager module contains the OAuthManager.
pub mod manager;
/// The token module contains the token provider trait, validation and flow.
pub mod token;
/// The util module contains utility functions.
pub mod util;
/// Test module, contains test support code, unit tests and integration tests.
#[cfg(any(test, feature = "_doctest"))]
pub mod test;
