//! Redis storage layer for pastes, users, sessions, and challenges.
//!
//! All functions are async and use redis::AsyncCommands.
//! Data is serialized to JSON for storage in Redis.

pub mod paste;
pub mod session;
pub mod user;
