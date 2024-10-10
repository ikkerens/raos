#[cfg(test)]
mod unit_test;
/// Mock implementations for testing.
pub mod mock;
/// Mock implementations for doctesting
#[cfg(feature = "_doctest")]
pub mod doctest;
