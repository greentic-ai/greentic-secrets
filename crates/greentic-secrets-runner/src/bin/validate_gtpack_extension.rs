use std::env;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use greentic_types::{PROVIDER_EXTENSION_ID, PackManifest, decode_pack_manifest};
use serde_yaml::Value;
use zip::ZipArchive;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err("Usage: validate-gtpack-extension <pack.gtpack> [pack2.gtpack ...]".into());
    }

    for pack in args {
        validate_pack(&pack)?;
    }

    Ok(())
}

fn validate_pack(pack: &str) -> Result<(), String> {
    let path = Path::new(pack);
    let file = File::open(path).map_err(|err| format!("[ERROR] open {}: {err}", pack))?;
    let mut archive =
        ZipArchive::new(file).map_err(|err| format!("[ERROR] {}: open zip: {err}", pack))?;
    if let Some(bytes) = read_member_bytes(&mut archive, "manifest.cbor") {
        let manifest = decode_pack_manifest(&bytes)
            .map_err(|err| format!("[ERROR] {}: decode manifest.cbor: {err}", pack))?;
        validate_manifest(pack, &manifest)?;
    } else if let Some(bytes) = read_member_bytes(&mut archive, "gtpack.yaml") {
        eprintln!(
            "[WARN] {}: manifest.cbor missing; falling back to gtpack.yaml validation",
            pack
        );
        validate_yaml(pack, &bytes)?;
    } else {
        return Err(format!(
            "[ERROR] {}: missing manifest.cbor and gtpack.yaml",
            pack
        ));
    }

    println!("{pack}: provider extension ok");
    Ok(())
}

fn read_member_bytes<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name_suffix: &str,
) -> Option<Vec<u8>> {
    for idx in 0..archive.len() {
        let mut file = archive.by_index(idx).ok()?;
        if file.is_dir() {
            continue;
        }
        if file.name().ends_with(name_suffix) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                return Some(buf);
            }
        }
    }
    None
}

fn validate_manifest(pack: &str, manifest: &PackManifest) -> Result<(), String> {
    let extensions = manifest
        .extensions
        .as_ref()
        .ok_or_else(|| format!("[ERROR] {}: missing extensions map", pack))?;
    let provider = extensions.get(PROVIDER_EXTENSION_ID).ok_or_else(|| {
        format!(
            "[ERROR] {}: missing canonical provider extension key {}",
            pack, PROVIDER_EXTENSION_ID
        )
    })?;
    if provider.kind != PROVIDER_EXTENSION_ID {
        return Err(format!(
            "[ERROR] {}: provider extension kind {} != {}",
            pack, provider.kind, PROVIDER_EXTENSION_ID
        ));
    }
    if provider.version != "1.0.0" {
        return Err(format!(
            "[ERROR] {}: provider extension version {} != 1.0.0",
            pack, provider.version
        ));
    }
    Ok(())
}

fn validate_yaml(pack: &str, yaml_bytes: &[u8]) -> Result<(), String> {
    let doc: Value = serde_yaml::from_slice(yaml_bytes)
        .map_err(|err| format!("[ERROR] {}: parse gtpack.yaml: {err}", pack))?;
    let extensions = doc.get("extensions").ok_or_else(|| {
        format!(
            "[ERROR] {}: missing extensions map while reading gtpack.yaml",
            pack
        )
    })?;
    let provider = extensions.get(PROVIDER_EXTENSION_ID).ok_or_else(|| {
        format!(
            "[ERROR] {}: missing canonical provider extension key {} in gtpack.yaml",
            pack, PROVIDER_EXTENSION_ID
        )
    })?;
    let kind = provider
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "[ERROR] {}: missing provider extension kind in gtpack.yaml",
                pack
            )
        })?;
    if kind != PROVIDER_EXTENSION_ID {
        return Err(format!(
            "[ERROR] {}: provider extension kind {} != {} in gtpack.yaml",
            pack, kind, PROVIDER_EXTENSION_ID
        ));
    }
    let version = provider
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if version != "1.0.0" {
        return Err(format!(
            "[ERROR] {}: provider extension version {} != 1.0.0 in gtpack.yaml",
            pack, version
        ));
    }

    Ok(())
}
