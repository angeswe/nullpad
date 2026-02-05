//! Authentication layer for Ed25519 signature verification and session management.

pub mod middleware;
pub mod session;
pub mod verify;

pub use middleware::{AdminSession, AppState, AuthSession, check_rate_limit};
pub use session::{generate_challenge_nonce, generate_session_token};
pub use verify::verify_signature;
