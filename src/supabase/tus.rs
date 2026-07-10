//! TUS 1.0.0 resumable-upload session registry for `/storage/v1`.
//!
//! Placeholder: holds no state yet and wires up no routes. Replaced by a real
//! implementation (creation / head / patch / termination handlers plus
//! `multipart/form-data` support) in a later slice.

/// In-memory registry of in-flight resumable-upload sessions, shared across a
/// gateway process via [`crate::supabase::gateway::AppState`].
#[derive(Default)]
pub struct TusRegistry;

impl TusRegistry {
    pub fn new() -> Self {
        Self
    }
}
