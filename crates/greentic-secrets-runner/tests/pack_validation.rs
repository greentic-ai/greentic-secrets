use std::fs;
use std::path::PathBuf;

use serde_yaml::Value;

fn packs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("packs")
}

#[test]
fn provider_packs_have_provider_core_extension_and_schemas() {
    let packs = ["aws-sm", "azure-kv", "gcp-sm", "k8s", "vault-kv"];
    for pack in packs {
        let pack_dir = packs_root().join(pack);
        let gtpack_path = pack_dir.join("gtpack.yaml");
        let raw = fs::read_to_string(&gtpack_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", gtpack_path.display()));
        let doc: Value = serde_yaml::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", gtpack_path.display()));

        let extensions = doc
            .get("extensions")
            .and_then(|v| v.get("greentic.ext.provider"))
            .unwrap_or_else(|| {
                panic!("missing greentic.ext.provider in {}", gtpack_path.display())
            });
        let runtime = extensions
            .get("provider")
            .and_then(|v| v.get("runtime"))
            .unwrap_or_else(|| panic!("missing runtime in {}", gtpack_path.display()));
        let world = runtime
            .get("world")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.world in {}", gtpack_path.display()));
        assert_eq!(
            world,
            "greentic:provider-schema-core/schema-core@1.0.0",
            "provider-core world mismatch in {}",
            gtpack_path.display()
        );
        let export = runtime
            .get("export")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.export in {}", gtpack_path.display()));
        assert_eq!(
            export,
            "invoke",
            "export must be invoke in {}",
            gtpack_path.display()
        );
        runtime
            .get("component_ref")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!("missing runtime.component_ref in {}", gtpack_path.display())
            });

        for rel in [
            "schema/config.schema.json",
            "schema/secrets-required.schema.json",
        ] {
            let path = pack_dir.join(rel);
            assert!(path.exists(), "missing required schema {}", path.display());
        }
    }
}
