#[cfg(feature = "memory-impls")]
pub use memory_authorization_provider::*;

#[cfg(feature = "memory-impls")]
mod memory_authorization_provider;