/// Static metadata describing a secret dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretSpec {
    /// Stable, machine readable key (e.g. `"TELEGRAM_TOKEN"`).
    pub name: &'static str,
    /// Optional human-facing hint used in prompts or documentation.
    pub description: Option<&'static str>,
}

/// Trait implemented by zero-sized marker types to surface secret specs.
pub trait SecretDescribable {
    /// Return the static list of secrets required by the component.
    fn secret_specs() -> &'static [SecretSpec];
}
