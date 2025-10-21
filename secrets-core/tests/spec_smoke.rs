use secrets_core::{SecretDescribable, SecretSpec};

struct Demo;

impl SecretDescribable for Demo {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "DEMO_KEY",
            description: Some("Demo key"),
        }]
    }
}

#[test]
fn smoke() {
    let specs = Demo::secret_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "DEMO_KEY");
    assert_eq!(specs[0].description, Some("Demo key"));
}
