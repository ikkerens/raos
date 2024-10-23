#[cfg(test)]
pub(crate) use test_environment::*;

/// Mock implementations for doctesting
#[cfg(feature = "_doctest")]
pub mod doctest;
/// Mock implementations for testing.
pub mod mock;
#[cfg(test)]
mod test_environment;

// TODO More unit tests for REQUIRED
// TODO More unit tests for SHALL
// TODO More unit tests for SHOULD

// TODO Add resource request support
// TODO Prepare MUST requirements for resource requests
