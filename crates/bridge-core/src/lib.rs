pub mod tunnel;
pub mod inspect;
pub mod posture;
pub mod dns;
pub mod policy;
pub mod identity;
pub mod api_types;

/// Bridge core version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
