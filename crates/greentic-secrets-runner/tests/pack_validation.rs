use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use greentic_types::{PROVIDER_EXTENSION_ID, decode_pack_manifest};
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
        let gtpack_path = pack_dir.join("gtpack.yaml");
        let raw = fs::read_to_string(&gtpack_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", gtpack_path.display()));
        let doc: Value = serde_yaml::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", gtpack_path.display()));

        let extensions = doc
            .get("extensions")
            .and_then(|v| v.get(PROVIDER_EXTENSION_ID))
            .unwrap_or_else(|| {
                panic!(
                    "missing {} in {}",
                    PROVIDER_EXTENSION_ID,
                    gtpack_path.display()
                )
            });
        let kind = extensions
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing kind in {}", gtpack_path.display()));
        assert_eq!(
            kind,
            PROVIDER_EXTENSION_ID,
            "provider extension kind mismatch in {}",
            gtpack_path.display()
        );
        let version = extensions
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing extension version in {}", gtpack_path.display()));
        assert_eq!(
            version,
            "1.0.0",
            "provider extension version must be 1.0.0 in {}",
            gtpack_path.display()
        );
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
        let manifest_bytes = read_pack_member(&pack, "manifest.cbor");
        if let Some(bytes) = manifest_bytes {
            let manifest = decode_pack_manifest(&bytes)
                .unwrap_or_else(|err| panic!("decode manifest from {}: {err}", pack.display()));
            let extensions = manifest
                .extensions
                .as_ref()
                .unwrap_or_else(|| panic!("{} missing extensions", pack.display()));
            let provider = extensions.get(PROVIDER_EXTENSION_ID).unwrap_or_else(|| {
                panic!(
                    "{} missing provider extension {}",
                    pack.display(),
                    PROVIDER_EXTENSION_ID
                )
            });
            assert_eq!(
                provider.kind,
                PROVIDER_EXTENSION_ID,
                "provider extension kind mismatch in {}",
                pack.display()
            );
            assert_eq!(
                provider.version,
                "1.0.0",
                "provider extension version mismatch in {}",
                pack.display()
            );
        } else {
            let yaml_bytes = read_pack_member(&pack, "gtpack.yaml")
                .unwrap_or_else(|| panic!("{} missing gtpack.yaml", pack.display()));
            let doc: Value = serde_yaml::from_slice(&yaml_bytes)
                .unwrap_or_else(|err| panic!("parse gtpack.yaml from {}: {err}", pack.display()));
            let extensions = doc
                .get("extensions")
                .and_then(|v| v.get(PROVIDER_EXTENSION_ID))
                .unwrap_or_else(|| {
                    panic!(
                        "{} missing extensions.{}",
                        pack.display(),
                        PROVIDER_EXTENSION_ID
                    )
                });
            let kind = extensions
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing kind in {}", pack.display()));
            assert_eq!(
                kind,
                PROVIDER_EXTENSION_ID,
                "provider extension kind mismatch in {}",
                pack.display()
            );
            let version = extensions
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing version in {}", pack.display()));
            assert_eq!(
                version,
                "1.0.0",
                "provider extension version mismatch in {}",
                pack.display()
            );
        }
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
