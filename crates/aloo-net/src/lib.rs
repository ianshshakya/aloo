//! `aloo-net` — Network Operations.
//!
//! Handles raw socket creation, TCP connects, and UDP sends.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod tcp;
pub mod target;

pub use target::TargetSpec;
