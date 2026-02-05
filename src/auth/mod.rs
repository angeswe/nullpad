//! Authentication layer for Ed25519 signature verification and session management.

pub mod middleware;
pub mod session;
pub mod verify;

pub use middleware::{check_rate_limit, AdminSession, AppState, AuthSession};
pub use session::{generate_challenge_nonce, generate_session_token};
pub use verify::verify_signature;
