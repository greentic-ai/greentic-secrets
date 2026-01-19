use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use greentic_types::PROVIDER_EXTENSION_ID;
use serde_json::Value as JsonValue;
use serde_yaml::Value;
use zip::ZipArchive;

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
        let pack_yaml = pack_dir.join("pack.yaml");
        let raw = fs::read_to_string(&pack_yaml)
            .unwrap_or_else(|e| panic!("read {}: {e}", pack_yaml.display()));
        let doc: Value = serde_yaml::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", pack_yaml.display()));

        let extensions = doc
            .get("extensions")
            .and_then(|v| v.get(PROVIDER_EXTENSION_ID))
            .unwrap_or_else(|| {
                panic!(
                    "missing {} in {}",
                    PROVIDER_EXTENSION_ID,
                    pack_yaml.display()
                )
            });
        let kind = extensions
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing kind in {}", pack_yaml.display()));
        assert_eq!(
            kind,
            PROVIDER_EXTENSION_ID,
            "provider extension kind mismatch in {}",
            pack_yaml.display()
        );
        let version = extensions
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing extension version in {}", pack_yaml.display()));
        assert_eq!(
            version,
            "1.0.0",
            "provider extension version must be 1.0.0 in {}",
            pack_yaml.display()
        );
        let provider = extensions
            .get("inline")
            .and_then(|v| v.get("providers"))
            .and_then(|v| v.get(0))
            .unwrap_or_else(|| panic!("missing inline.providers in {}", pack_yaml.display()));
        let runtime = provider
            .get("runtime")
            .unwrap_or_else(|| panic!("missing runtime in {}", pack_yaml.display()));
        let config_schema = provider
            .get("config_schema_ref")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(
            config_schema,
            "assets/schema/config.schema.json",
            "provider config schema ref mismatch in {}",
            pack_yaml.display()
        );
        let world = runtime
            .get("world")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.world in {}", pack_yaml.display()));
        assert_eq!(
            world,
            "greentic:provider/schema-core@1.0.0",
            "provider-core world mismatch in {}",
            pack_yaml.display()
        );
        let export = runtime
            .get("export")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.export in {}", pack_yaml.display()));
        assert_eq!(
            export,
            "invoke",
            "export must be invoke in {}",
            pack_yaml.display()
        );
        runtime
            .get("component_ref")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.component_ref in {}", pack_yaml.display()));

        for rel in [
            "schema/config.schema.json",
            "schema/secrets-required.schema.json",
        ] {
            let path = pack_dir.join(rel);
            assert!(path.exists(), "missing required schema {}", path.display());
        }
    }
}

#[test]
fn built_provider_gtpacks_embed_canonical_provider_extension() {
    let packs = packs_root();
    let repo_root = packs
        .parent()
        .unwrap_or_else(|| panic!("packs directory missing parent for {}", packs.display()));
    let status = Command::new("bash")
        .arg("scripts/build-provider-packs.sh")
        .current_dir(repo_root)
        .env(
            "VALIDATE_GTPACK_BIN",
            env!("CARGO_BIN_EXE_validate_gtpack_extension"),
        )
        .status()
        .expect("spawn build-provider-packs.sh");
    assert!(
        status.success(),
        "build-provider-packs.sh failed with status {:?}",
        status.code()
    );

    let out_dir = repo_root.join("target").join("provider-packs");
    let mut packs = Vec::new();
    for entry in
        fs::read_dir(&out_dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", out_dir.display()))
    {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("gtpack"))
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name != "secrets-providers.gtpack")
        {
            packs.push(path);
        }
    }
    assert!(
        !packs.is_empty(),
        "no .gtpack artifacts produced in {}",
        out_dir.display()
    );

    for pack in packs {
        let manifest_bytes = read_pack_member(&pack, "manifest.cbor")
            .unwrap_or_else(|| panic!("{} missing manifest.cbor", pack.display()));
        let doc: JsonValue = serde_cbor::from_slice(&manifest_bytes)
            .unwrap_or_else(|err| panic!("decode manifest from {}: {err}", pack.display()));
        let extensions = doc
            .get("extensions")
            .unwrap_or_else(|| panic!("{} missing extensions", pack.display()));
        let provider = extensions.get(PROVIDER_EXTENSION_ID).unwrap_or_else(|| {
            panic!(
                "{} missing provider extension {}",
                pack.display(),
                PROVIDER_EXTENSION_ID
            )
        });
        let kind = provider
            .get("kind")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        assert_eq!(
            kind,
            PROVIDER_EXTENSION_ID,
            "provider extension kind mismatch in {}",
            pack.display()
        );
        let version = provider
            .get("version")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        assert_eq!(
            version,
            "1.0.0",
            "provider extension version mismatch in {}",
            pack.display()
        );
    }
}

fn read_pack_member(pack: &PathBuf, name_suffix: &str) -> Option<Vec<u8>> {
    let file = File::open(pack).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).ok()?;
        if entry.is_dir() {
            continue;
        }
        if entry.name().ends_with(name_suffix) {
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_ok() {
                return Some(buf);
            }
        }
    }
    None
}
