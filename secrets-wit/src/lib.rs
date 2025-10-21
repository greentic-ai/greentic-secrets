//! Provides access to the WIT definitions used by the secrets platform.

pub const SECRETS_WORLD: &str = include_str!("../wit/greentic.secrets@0.1.0.wit");

pub fn secrets_world() -> &'static str {
    SECRETS_WORLD
}
