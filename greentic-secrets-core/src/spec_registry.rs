use crate::SecretSpec;
use serde_json::json;
use std::collections::BTreeMap;

/// Registry that merges secrets declared by multiple components.
#[derive(Default)]
pub struct SecretSpecRegistry {
    by_name: BTreeMap<&'static str, SecretSpec>,
}

impl SecretSpecRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend the registry with additional specs, deduplicating by name.
    pub fn extend_with(&mut self, specs: &'static [SecretSpec]) {
        for spec in specs {
            match self.by_name.get(spec.name) {
                None => {
                    self.by_name.insert(spec.name, spec.clone());
                }
                Some(existing) => {
                    let better = match (existing.description, spec.description) {
                        (None, Some(_)) => true,
                        (Some(a), Some(b)) if b.len() > a.len() => true,
                        _ => false,
                    };
                    if better {
                        self.by_name.insert(spec.name, spec.clone());
                    }
                }
            }
        }
    }

    /// Iterate over all stored specs in deterministic order.
    pub fn all(&self) -> impl Iterator<Item = &SecretSpec> {
        self.by_name.values()
    }

    /// Render the registry to a Markdown table suitable for CLI output.
    pub fn to_markdown_table(&self) -> String {
        let mut out = String::from("| Name | Description |\n|---|---|\n");
        for spec in self.by_name.values() {
            let desc = spec.description.unwrap_or("");
            out.push_str(&format!("| `{}` | {} |\n", spec.name, desc));
        }
        out
    }

    /// Render the registry as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let entries = self
            .by_name
            .values()
            .map(|spec| {
                json!({
                    "name": spec.name,
                    "description": spec.description,
                })
            })
            .collect();
        serde_json::Value::Array(entries)
    }
}
