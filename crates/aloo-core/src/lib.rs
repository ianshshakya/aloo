//! `aloo-core` — Pure domain model.
//!
//! No async, no I/O, no network code. Every other crate in the workspace
//! depends on this crate; this crate depends on nothing internal.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod id;
pub mod types;

pub use error::{AlooError, AlooResult};
pub use id::{HostId, PortId, SessionId};
pub use types::*;
