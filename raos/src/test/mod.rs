/// Mock implementations for doctesting
#[cfg(feature = "_doctest")]
pub mod doctest;
/// Mock implementations for testing.
pub mod mock;
#[cfg(test)]
mod unit_test;
