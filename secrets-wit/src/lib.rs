//! Provides access to the WIT definitions used by the secrets platform.

pub const BROKER_WORLD: &str = include_str!("../wit/broker.wit");

pub fn broker_world() -> &'static str {
    BROKER_WORLD
}
