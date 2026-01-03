//! Vera E2E-encrypted sync wire types and record envelope.

pub mod envelope;
pub mod protocol;

pub use protocol::{PullResponse, PushItem, SyncRecord};
