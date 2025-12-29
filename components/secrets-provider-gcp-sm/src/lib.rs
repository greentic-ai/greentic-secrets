use base64::{engine::general_purpose, Engine};
#[cfg(target_arch = "wasm32")]
mod bindings {
    include!("../../common/schema_core_api.rs");
}
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

fn to_bytes(val: Value) -> Result<Vec<u8>, String> {
    match val {
        Value::String(s) => match general_purpose::STANDARD.decode(&s) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Ok(s.into_bytes()),
        },
        Value::Array(arr) => {
            let mut out = Vec::new();
            for v in arr {
                out.push(
                    v.as_u64()
                        .ok_or_else(|| "array must contain bytes".to_string())?
                        as u8,
                );
            }
            Ok(out)
        }
        _ => Err("value must be string (b64 or utf8) or byte array".to_string()),
    }
}

fn from_bytes(bytes: &[u8]) -> Value {
    Value::String(general_purpose::STANDARD.encode(bytes))
}

fn ok<T: Serialize>(payload: T) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap_or_else(|e| err(e.to_string()))
}

fn err(msg: impl Into<String>) -> Vec<u8> {
    ok(serde_json::json!({ "status": "error", "message": msg.into() }))
}

pub struct Provider;

#[cfg(not(target_arch = "wasm32"))]
mod host {
    use super::*;
    use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
    use google_cloud_secretmanager_v1::{
        client::SecretManagerService,
        model::{
            replication, AccessSecretVersionRequest, AddSecretVersionRequest, CreateSecretRequest,
            Replication, Secret, SecretPayload,
        },
    };
    use once_cell::sync::{Lazy, OnceCell};
    use tokio::runtime::Runtime;

    #[derive(Deserialize, Clone, Default)]
    struct Config {
        project_id: String,
        #[serde(default)]
        endpoint: Option<String>,
    }

    #[derive(Deserialize)]
    struct PutInput {
        key: String,
        value: Value,
    }

    #[derive(Deserialize)]
    struct KeyInput {
        key: String,
    }

    struct GcpCtx {
        rt: Runtime,
        client: SecretManagerService,
        project: String,
    }

    static CTX: OnceCell<GcpCtx> = OnceCell::new();
    static FAKE: Lazy<bool> =
        Lazy::new(|| std::env::var("GREENTIC_GCP_FAKE").is_ok() || cfg!(test));
    static STORE: Lazy<Mutex<HashMap<String, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    fn client_from_config(cfg: Config) -> Result<GcpCtx, String> {
        let rt = Runtime::new().map_err(|e| format!("runtime init: {e}"))?;
        let project = cfg.project_id.clone();
        let client = rt.block_on(async move {
            let mut builder = SecretManagerService::builder();
            if let Some(endpoint) = cfg.endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            builder
                .build()
                .await
                .map_err(|e| format!("client init: {e}"))
        })?;
        Ok(GcpCtx {
            rt,
            client,
            project,
        })
    }

    fn ctx(cfg_json: &[u8]) -> Result<&'static GcpCtx, String> {
        CTX.get_or_try_init(|| {
            let cfg: Config =
                serde_json::from_slice(cfg_json).map_err(|e| format!("config parse: {e}"))?;
            client_from_config(cfg)
        })
        .map_err(|e| e.to_string())
    }

    fn handle_put(ctx: &GcpCtx, key: String, value: Value) -> Vec<u8> {
        let bytes = match to_bytes(value) {
            Ok(b) => b,
            Err(e) => return err(e),
        };
        let client = ctx.client.clone();
        let parent = format!("projects/{}/secrets/{}", ctx.project, key);
        let res = ctx.rt.block_on(async move {
            let payload = SecretPayload::new().set_data(bytes.clone());
            let req = AddSecretVersionRequest::new()
                .set_parent(parent.clone())
                .set_payload(payload);
            match client.add_secret_version().with_request(req).send().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    if format!("{e}").contains("NotFound") {
                        // Create then retry once.
                        ensure_secret_host(&client, &parent, &bytes).await?;
                        let retry_req = AddSecretVersionRequest::new()
                            .set_parent(parent)
                            .set_payload(SecretPayload::new().set_data(bytes));
                        client
                            .add_secret_version()
                            .with_request(retry_req)
                            .send()
                            .await
                            .map(|_| ())
                            .map_err(|err| format!("{err}"))
                    } else {
                        Err(format!("{e}"))
                    }
                }
            }
        });
        match res {
            Ok(_) => ok(serde_json::json!({ "status": "ok" })),
            Err(e) => err(e),
        }
    }

    async fn ensure_secret_host(
        client: &SecretManagerService,
        parent: &str,
        initial: &[u8],
    ) -> Result<(), String> {
        let parts: Vec<&str> = parent.split("/secrets/").collect();
        if parts.len() != 2 {
            return Err("invalid parent".to_string());
        }
        let project = parts[0].trim_start_matches("projects/").to_string();
        let secret_id = parts[1].to_string();
        let replication = Replication::new().set_replication(Some(
            replication::Replication::Automatic(replication::Automatic::default().into()),
        ));
        let req = CreateSecretRequest::new()
            .set_parent(format!("projects/{}", project))
            .set_secret_id(secret_id)
            .set_secret(Secret::new().set_replication(replication));
        let _ = client
            .create_secret()
            .with_request(req)
            .send()
            .await
            .map_err(|e| format!("{e}"))?;
        let add_req = AddSecretVersionRequest::new()
            .set_parent(parent.to_string())
            .set_payload(SecretPayload::new().set_data(initial.to_vec()));
        client
            .add_secret_version()
            .with_request(add_req)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| format!("{e}"))
    }

    fn handle_get(ctx: &GcpCtx, key: String) -> Vec<u8> {
        let client = ctx.client.clone();
        let name = format!("projects/{}/secrets/{}/versions/latest", ctx.project, key);
        let res = ctx.rt.block_on(async move {
            let req = AccessSecretVersionRequest::new().set_name(name);
            let out = client
                .access_secret_version()
                .with_request(req)
                .send()
                .await
                .map_err(|e| format!("{e}"))?;
            let payload = out.payload.ok_or_else(|| "missing payload".to_string())?;
            Ok::<Vec<u8>, String>(payload.data.to_vec())
        });
        match res {
            Ok(b) => ok(serde_json::json!({ "value": from_bytes(&b) })),
            Err(e) => err(e),
        }
    }

    fn handle_delete(ctx: &GcpCtx, key: String) -> Vec<u8> {
        let client = ctx.client.clone();
        let name = format!("projects/{}/secrets/{}", ctx.project, key);
        let res = ctx.rt.block_on(async move {
            client
                .delete_secret()
                .set_name(name)
                .send()
                .await
                .map_err(|e| format!("{e}"))
                .map(|_| ())
        });
        match res {
            Ok(_) => ok(serde_json::json!({ "status": "ok" })),
            Err(e) => err(e),
        }
    }

    fn handle_inmemory(op: String, parsed: serde_json::Value) -> Vec<u8> {
        match op.as_str() {
            "put" => {
                let input: PutInput = match serde_json::from_value(parsed) {
                    Ok(v) => v,
                    Err(e) => return err(format!("invalid put input: {e}")),
                };
                let bytes = match to_bytes(input.value) {
                    Ok(b) => b,
                    Err(e) => return err(e),
                };
                let mut store = STORE.lock().expect("store lock");
                store.insert(input.key, bytes);
                ok(serde_json::json!({ "status": "ok" }))
            }
            "get" => {
                let input: KeyInput = match serde_json::from_value(parsed) {
                    Ok(v) => v,
                    Err(e) => return err(format!("invalid get input: {e}")),
                };
                let store = STORE.lock().expect("store lock");
                let val = match store.get(&input.key) {
                    Some(v) => v,
                    None => return err("not found"),
                };
                ok(serde_json::json!({ "value": from_bytes(val) }))
            }
            "delete" => {
                let input: KeyInput = match serde_json::from_value(parsed) {
                    Ok(v) => v,
                    Err(e) => return err(format!("invalid delete input: {e}")),
                };
                let mut store = STORE.lock().expect("store lock");
                store.remove(&input.key);
                ok(serde_json::json!({ "status": "ok" }))
            }
            _ => err("unsupported op"),
        }
    }

    impl schema_core_api::Guest for Provider {
        fn describe() -> Vec<u8> {
            ok(serde_json::json!({
                "provider_type": "secrets",
                "id": "gcp-sm",
                "capabilities": ["get", "put", "delete"],
                "ops": ["get", "put", "delete"]
            }))
        }

        fn validate_config(config_json: Vec<u8>) -> schema_core_api::ValidationResult {
            if serde_json::from_slice::<Config>(&config_json).is_err() {
                return err("invalid config json");
            }
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn healthcheck() -> schema_core_api::HealthStatus {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn invoke(op: String, input_json: Vec<u8>) -> schema_core_api::InvokeResult {
            let parsed: serde_json::Value = match serde_json::from_slice(&input_json) {
                Ok(v) => v,
                Err(e) => return err(format!("invalid input json: {e}")),
            };
            if *FAKE {
                return handle_inmemory(op, parsed);
            }
            let ctx = match ctx(&input_json) {
                Ok(c) => c,
                Err(e) => return err(e),
            };
            match op.as_str() {
                "put" => {
                    let input: PutInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid put input: {e}")),
                    };
                    handle_put(ctx, input.key, input.value)
                }
                "get" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid get input: {e}")),
                    };
                    handle_get(ctx, input.key)
                }
                "delete" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid delete input: {e}")),
                    };
                    handle_delete(ctx, input.key)
                }
                _ => err("unsupported op"),
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    #[allow(unused_imports)]
    use bindings::exports::greentic::provider_schema_core::schema_core_api;
    use once_cell::sync::Lazy;

    #[derive(Deserialize)]
    struct PutInput {
        key: String,
        value: Value,
    }

    #[derive(Deserialize)]
    struct KeyInput {
        key: String,
    }

    static STORE: Lazy<Mutex<HashMap<String, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    impl schema_core_api::Guest for Provider {
        fn describe() -> Vec<u8> {
            ok(serde_json::json!({
                "provider_type": "secrets",
                "id": "gcp-sm",
                "capabilities": ["get", "put", "delete"],
                "ops": ["get", "put", "delete"]
            }))
        }

        fn validate_config(_config_json: Vec<u8>) -> schema_core_api::ValidationResult {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn healthcheck() -> schema_core_api::HealthStatus {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn invoke(op: String, input_json: Vec<u8>) -> schema_core_api::InvokeResult {
            let parsed: serde_json::Value = match serde_json::from_slice(&input_json) {
                Ok(v) => v,
                Err(e) => return err(format!("invalid input json: {e}")),
            };
            match op.as_str() {
                "put" => {
                    let input: PutInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid put input: {e}")),
                    };
                    let bytes = match to_bytes(input.value) {
                        Ok(b) => b,
                        Err(e) => return err(e),
                    };
                    let mut store = STORE.lock().expect("store lock");
                    store.insert(input.key, bytes);
                    ok(serde_json::json!({ "status": "ok" }))
                }
                "get" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid get input: {e}")),
                    };
                    let store = STORE.lock().expect("store lock");
                    let val = match store.get(&input.key) {
                        Some(v) => v,
                        None => return err("not found"),
                    };
                    ok(serde_json::json!({ "value": from_bytes(val) }))
                }
                "delete" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid delete input: {e}")),
                    };
                    let mut store = STORE.lock().expect("store lock");
                    store.remove(&input.key);
                    ok(serde_json::json!({ "status": "ok" }))
                }
                _ => err("unsupported op"),
            }
        }
    }

    schema_core_api::__export_greentic_provider_schema_core_schema_core_api_1_0_0_cabi!(Provider with_types_in bindings::exports::greentic::provider_schema_core::schema_core_api);
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
    use schema_core_api::Guest;

    fn json_bytes(val: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&val).expect("json")
    }

    fn as_json(bytes: Vec<u8>) -> serde_json::Value {
        serde_json::from_slice(&bytes).expect("json")
    }

    #[test]
    fn roundtrip_put_get_delete() {
        std::env::set_var("GREENTIC_GCP_FAKE", "1");
        let meta = as_json(Provider::describe());
        assert_eq!(
            meta.get("provider_type").and_then(|v| v.as_str()),
            Some("secrets")
        );

        let validated = Provider::validate_config(
            serde_json::to_vec(&serde_json::json!({"project_id": "proj"})).unwrap(),
        );
        assert_eq!(
            as_json(validated).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let put = Provider::invoke(
            "put".into(),
            json_bytes(serde_json::json!({"key": "k1", "value": "secret"})),
        );
        assert_eq!(
            as_json(put).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let get = Provider::invoke("get".into(), json_bytes(serde_json::json!({"key": "k1"})));
        let get_json = as_json(get);
        let val_b64 = get_json
            .get("value")
            .and_then(|v| v.as_str())
            .expect("value");
        let decoded = general_purpose::STANDARD
            .decode(val_b64)
            .unwrap_or_default();
        assert!(!decoded.is_empty());

        let del = Provider::invoke(
            "delete".into(),
            json_bytes(serde_json::json!({"key": "k1"})),
        );
        assert_eq!(
            as_json(del).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );
    }
}
