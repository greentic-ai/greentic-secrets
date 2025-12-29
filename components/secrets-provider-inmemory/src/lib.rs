use std::collections::HashMap;
use std::sync::Mutex;

use base64::{engine::general_purpose, Engine};
#[cfg(not(target_arch = "wasm32"))]
use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
#[cfg(target_arch = "wasm32")]
mod bindings {
    include!("../../common/schema_core_api.rs");
}
#[cfg(target_arch = "wasm32")]
use bindings::exports::greentic::provider_schema_core::schema_core_api;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Default)]
pub struct InMemoryProvider;

#[derive(Default)]
struct Store {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

static STORE: Lazy<Store> = Lazy::new(Store::default);

#[derive(Deserialize)]
struct PutInput {
    key: String,
    value: Value,
}

#[derive(Deserialize)]
struct GetDeleteInput {
    key: String,
}

#[derive(Serialize)]
struct GetOutput {
    value: Value,
}

#[derive(Serialize)]
struct DeleteOutput {
    status: &'static str,
}

fn ok<T: Serialize>(payload: T) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap_or_else(|e| err(e.to_string()))
}

fn err(msg: impl Into<String>) -> Vec<u8> {
    ok(serde_json::json!({ "status": "error", "message": msg.into() }))
}

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

impl schema_core_api::Guest for InMemoryProvider {
    fn describe() -> Vec<u8> {
        ok(serde_json::json!({
            "provider_type": "secrets",
            "id": "inmemory",
            "capabilities": ["get", "put", "delete"],
            "ops": ["get", "put", "delete"]
        }))
    }

    fn validate_config(config_json: Vec<u8>) -> schema_core_api::ValidationResult {
        if serde_json::from_slice::<serde_json::Value>(&config_json).is_err() {
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
                let mut store = STORE.inner.lock().expect("store lock");
                store.insert(input.key, bytes);
                ok(serde_json::json!({ "status": "ok" }))
            }
            "get" => {
                let input: GetDeleteInput = match serde_json::from_value(parsed) {
                    Ok(v) => v,
                    Err(e) => return err(format!("invalid get input: {e}")),
                };
                let store = STORE.inner.lock().expect("store lock");
                let val = match store.get(&input.key) {
                    Some(v) => v,
                    None => return err("not found"),
                };
                ok(GetOutput {
                    value: from_bytes(val),
                })
            }
            "delete" => {
                let input: GetDeleteInput = match serde_json::from_value(parsed) {
                    Ok(v) => v,
                    Err(e) => return err(format!("invalid delete input: {e}")),
                };
                let mut store = STORE.inner.lock().expect("store lock");
                store.remove(&input.key);
                ok(DeleteOutput { status: "ok" })
            }
            _ => err("unsupported op"),
        }
    }
}

#[allow(unused_macros)]
macro_rules! export_provider {
    ($ty:ident) => {
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#describe")]
        unsafe extern "C" fn export_describe() -> *mut u8 {
            schema_core_api::_export_describe_cabi::<$ty>()
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#describe")]
        unsafe extern "C" fn _post_return_describe(arg0: *mut u8) {
            schema_core_api::__post_return_describe::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#validate-config")]
        unsafe extern "C" fn export_validate_config(arg0: *mut u8, arg1: usize) -> *mut u8 {
            schema_core_api::_export_validate_config_cabi::<$ty>(arg0, arg1)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#validate-config")]
        unsafe extern "C" fn _post_return_validate_config(arg0: *mut u8) {
            schema_core_api::__post_return_validate_config::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#healthcheck")]
        unsafe extern "C" fn export_healthcheck() -> *mut u8 {
            schema_core_api::_export_healthcheck_cabi::<$ty>()
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#healthcheck")]
        unsafe extern "C" fn _post_return_healthcheck(arg0: *mut u8) {
            schema_core_api::__post_return_healthcheck::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#invoke")]
        unsafe extern "C" fn export_invoke(
            arg0: *mut u8,
            arg1: usize,
            arg2: *mut u8,
            arg3: usize,
        ) -> *mut u8 {
            schema_core_api::_export_invoke_cabi::<$ty>(arg0, arg1, arg2, arg3)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#invoke")]
        unsafe extern "C" fn _post_return_invoke(arg0: *mut u8) {
            schema_core_api::__post_return_invoke::<$ty>(arg0)
        }
    };
}

export_provider!(InMemoryProvider);

#[cfg(test)]
mod tests {
    use super::*;
    use schema_core_api::Guest;

    fn json_bytes(val: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&val).expect("json")
    }

    fn as_json(bytes: Vec<u8>) -> serde_json::Value {
        serde_json::from_slice(&bytes).expect("json")
    }

    #[test]
    fn roundtrip_put_get_delete() {
        // describe returns provider metadata json
        let meta = as_json(InMemoryProvider::describe());
        assert_eq!(
            meta.get("provider_type").and_then(|v| v.as_str()),
            Some("secrets")
        );

        // validate accepts basic json
        let validated = InMemoryProvider::validate_config(b"{}".to_vec());
        assert_eq!(
            as_json(validated).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        // put
        let put = InMemoryProvider::invoke(
            "put".into(),
            json_bytes(serde_json::json!({"key": "k1", "value": "secret"})),
        );
        assert_eq!(
            as_json(put).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        // get
        let get =
            InMemoryProvider::invoke("get".into(), json_bytes(serde_json::json!({"key": "k1"})));
        let get_json = as_json(get);
        let val_b64 = get_json
            .get("value")
            .and_then(|v| v.as_str())
            .expect("value");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(val_b64)
            .expect("b64");
        assert_eq!(decoded, b"secret");

        // delete
        let del = InMemoryProvider::invoke(
            "delete".into(),
            json_bytes(serde_json::json!({"key": "k1"})),
        );
        assert_eq!(
            as_json(del).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );
    }
}
