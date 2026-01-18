#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use greentic_types::{PackManifest, ProviderDecl, ProviderExtensionInline, decode_pack_manifest};

wit_bindgen::generate!({
    world: "pack-validator",
    path: "wit/greentic/pack-validate@0.1.0",
});

use exports::greentic::pack_validate::validator::{Diagnostic, Guest, PackInputs};

const SECRET_REQUIREMENTS_ASSET: &str = "assets/secret-requirements.json";
const SECRET_REQUIREMENTS_ASSET_ALT: &str = "assets/secret_requirements.json";

struct SecretsPackValidator;

impl Guest for SecretsPackValidator {
    fn applies(inputs: PackInputs) -> bool {
        let file_index = inputs.file_index;
        let asset_present = has_secret_requirements_asset(&file_index);
        if let Some(manifest) = decode_manifest(&inputs.manifest_cbor) {
            secrets_required(&manifest) || asset_present
        } else {
            asset_present
        }
    }

    fn validate(inputs: PackInputs) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        let file_index = inputs.file_index;
        let asset_present = has_secret_requirements_asset(&file_index);
        let manifest = decode_manifest(&inputs.manifest_cbor);
        let secrets_required = manifest
            .as_ref()
            .map(secrets_required)
            .unwrap_or(asset_present);

        if !secrets_required {
            return diagnostics;
        }

        if !asset_present {
            diagnostics.push(diagnostic(
                "error",
                "SEC_REQUIREMENTS_ASSET_MISSING",
                "Secret requirements asset is missing from the pack.",
                Some(SECRET_REQUIREMENTS_ASSET.to_owned()),
                Some("Add assets/secret-requirements.json to the pack.".to_owned()),
            ));
        }

        if !can_check_sensitivity() {
            diagnostics.push(diagnostic(
                "warn",
                "SEC_SECRET_NOT_SENSITIVE",
                "Secret requirements sensitivity checks require asset bytes.",
                Some(SECRET_REQUIREMENTS_ASSET.to_owned()),
                Some(
                    "Provide secret-requirements.json bytes to enable sensitivity checks."
                        .to_owned(),
                ),
            ));
        }

        if let Some(manifest) = manifest.as_ref() {
            diagnostics.extend(validate_key_format(manifest));
        }

        diagnostics
    }
}

#[cfg(target_arch = "wasm32")]
export!(SecretsPackValidator);

fn decode_manifest(bytes: &[u8]) -> Option<PackManifest> {
    decode_pack_manifest(bytes).ok()
}

fn has_secret_requirements_asset(file_index: &[String]) -> bool {
    file_index
        .iter()
        .any(|entry| entry == SECRET_REQUIREMENTS_ASSET || entry == SECRET_REQUIREMENTS_ASSET_ALT)
}

fn secrets_required(manifest: &PackManifest) -> bool {
    let pack_id = manifest.pack_id.as_str().to_ascii_lowercase();
    if pack_id.starts_with("secrets-") || pack_id.contains(".secrets.") {
        return true;
    }
    if !manifest.secret_requirements.is_empty() {
        return true;
    }
    manifest
        .provider_extension_inline()
        .map(provider_extension_mentions_secrets)
        .unwrap_or(false)
}

fn provider_extension_mentions_secrets(inline: &ProviderExtensionInline) -> bool {
    inline.providers.iter().any(provider_decl_mentions_secrets)
}

fn provider_decl_mentions_secrets(provider: &ProviderDecl) -> bool {
    let mut fields = Vec::new();
    fields.push(provider.provider_type.as_str());
    fields.push(provider.config_schema_ref.as_str());
    if let Some(state_schema_ref) = provider.state_schema_ref.as_ref() {
        fields.push(state_schema_ref.as_str());
    }
    if let Some(docs_ref) = provider.docs_ref.as_ref() {
        fields.push(docs_ref.as_str());
    }
    fields.push(provider.runtime.world.as_str());
    fields.push(provider.runtime.component_ref.as_str());

    fields
        .into_iter()
        .any(|value| value.to_ascii_lowercase().contains("secrets"))
}

fn validate_key_format(manifest: &PackManifest) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (idx, req) in manifest.secret_requirements.iter().enumerate() {
        let key = req.key.as_str();
        if key.is_empty() {
            continue;
        }
        if is_upper_snake(key) || key.starts_with("greentic://") {
            continue;
        }
        diagnostics.push(diagnostic(
            "warn",
            "SEC_BAD_KEY_FORMAT",
            "Secret requirement key format should be UPPER_SNAKE or greentic:// URI.",
            Some(format!("secret_requirements.{idx}.key")),
            Some("Rename the key to UPPER_SNAKE or a greentic:// URI.".to_owned()),
        ));
    }
    diagnostics
}

fn is_upper_snake(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn can_check_sensitivity() -> bool {
    false
}

fn diagnostic(
    severity: &str,
    code: &str,
    message: &str,
    path: Option<String>,
    hint: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity: severity.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
        path,
        hint,
    }
}
