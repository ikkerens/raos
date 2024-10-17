#[cfg(test)]
pub(crate) use test_environment::*;

/// Mock implementations for doctesting
#[cfg(feature = "_doctest")]
pub mod doctest;
/// Mock implementations for testing.
pub mod mock;
#[cfg(test)]
mod test_environment;
