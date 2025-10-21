use secrets_core::{SecretDescribable, SecretSpec, SecretSpecRegistry};

struct Alpha;
struct Beta;

impl SecretDescribable for Alpha {
    fn secret_specs() -> &'static [SecretSpec] {
        &[
            SecretSpec {
                name: "ALPHA",
                description: Some("first"),
            },
            SecretSpec {
                name: "SHARED",
                description: Some("short"),
            },
        ]
    }
}

impl SecretDescribable for Beta {
    fn secret_specs() -> &'static [SecretSpec] {
        &[
            SecretSpec {
                name: "BETA",
                description: None,
            },
            SecretSpec {
                name: "SHARED",
                description: Some("longer description"),
            },
        ]
    }
}

#[test]
fn merge_and_render() {
    let mut registry = SecretSpecRegistry::new();
    registry.extend_with(Alpha::secret_specs());
    registry.extend_with(Beta::secret_specs());

    let specs: Vec<_> = registry.all().collect();
    assert_eq!(specs.len(), 3);

    let markdown = registry.to_markdown_table();
    assert!(markdown.contains("`SHARED`") && markdown.contains("longer"));

    let json = registry.to_json();
    assert!(json.as_array().unwrap().len() == 3);
}
