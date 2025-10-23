use crate::SecretSpec;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Convert an iterator of secret specs into a JSON Schema value.
///
/// The resulting schema describes an object where each spec becomes a string
/// property. Specs are emitted in lexicographic order to keep the schema stable
/// for downstream tooling and snapshots.
pub fn specs_to_json_schema<'a>(specs: impl Iterator<Item = &'a SecretSpec>) -> Value {
    let mut ordered: BTreeMap<&'a str, &'a SecretSpec> = BTreeMap::new();
    for spec in specs {
        ordered.insert(spec.name, spec);
    }

    let mut properties = Map::new();
    for spec in ordered.values() {
        properties.insert(
            spec.name.to_string(),
            json!({
                "type": "string",
                "description": spec.description.unwrap_or(""),
            }),
        );
    }

    json!({
        "type": "object",
        "properties": properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretDescribable, SecretSpec};

    struct DemoA;
    struct DemoB;

    impl SecretDescribable for DemoA {
        fn secret_specs() -> &'static [SecretSpec] {
            &[
                SecretSpec {
                    name: "ALPHA",
                    description: Some("alpha description"),
                },
                SecretSpec {
                    name: "OMEGA",
                    description: None,
                },
            ]
        }
    }

    impl SecretDescribable for DemoB {
        fn secret_specs() -> &'static [SecretSpec] {
            &[SecretSpec {
                name: "BETA",
                description: Some("beta description"),
            }]
        }
    }

    #[test]
    fn schema_properties_are_stably_ordered() {
        let schema = specs_to_json_schema(
            DemoA::secret_specs()
                .iter()
                .chain(DemoB::secret_specs().iter()),
        );

        let object = schema.as_object().expect("schema object");
        assert_eq!(object.get("type").and_then(Value::as_str), Some("object"));

        let properties = object
            .get("properties")
            .and_then(Value::as_object)
            .expect("properties map");

        let ordered_keys: Vec<_> = properties.keys().cloned().collect();
        assert_eq!(ordered_keys, vec!["ALPHA", "BETA", "OMEGA"]);

        let alpha = properties
            .get("ALPHA")
            .and_then(Value::as_object)
            .expect("alpha schema");
        assert_eq!(alpha.get("type").and_then(Value::as_str), Some("string"));
        assert_eq!(
            alpha.get("description").and_then(Value::as_str),
            Some("alpha description")
        );
    }
}
