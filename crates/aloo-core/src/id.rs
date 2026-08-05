//! Strongly-typed ID wrappers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! new_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Create a new random ID.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            /// Return the inner UUID.
            pub fn inner(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
    };
}

new_id!(SessionId, "Unique identifier for a scan session.");
new_id!(HostId,    "Unique identifier for a discovered host.");
new_id!(PortId,    "Unique identifier for a scanned port.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        assert_ne!(SessionId::new(), SessionId::new());
        assert_ne!(HostId::new(), HostId::new());
    }

    #[test]
    fn id_roundtrip_json() {
        let id = HostId::new();
        let json = serde_json::to_string(&id).unwrap();
        let decoded: HostId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn id_display() {
        let id = SessionId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36); // UUID v4 string length
    }
}
