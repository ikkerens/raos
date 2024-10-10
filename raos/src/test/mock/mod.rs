#[cfg(any(test, feature = "_doctest"))]
mod request;
#[cfg(test)]
mod client;
#[cfg(test)]
mod token;
#[cfg(test)]
mod authorization;
#[cfg(test)]
mod manager;

#[cfg(test)]
pub(crate) use authorization::*;
#[cfg(test)]
pub(crate) use client::*;
#[cfg(test)]
pub(crate) use manager::*;
#[cfg(any(test, feature = "_doctest"))]
pub use request::*;
#[cfg(test)]
pub(crate) use token::*;
