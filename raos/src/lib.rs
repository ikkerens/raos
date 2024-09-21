#![forbid(unsafe_code)]
#![warn(
    // missing_docs,
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

pub mod authorize;
pub mod builder;
pub mod common;
pub mod manager;
pub mod token;
pub mod util;

#[cfg(test)]
mod test;
