//! Exposes the WIT definitions consumed by the broker host build.

/// Embedded WIT world describing the broker APIs.
pub const WORLD: &str = secrets_wit::SECRETS_WORLD;

/// Convenience accessor for the WIT world text.
pub fn world() -> &'static str {
    secrets_wit::secrets_world()
}
