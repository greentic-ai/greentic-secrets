use base64::{engine::general_purpose, Engine};
use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
use schema_core_api::Guest;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

fn json_bytes(val: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&val).expect("json serialize")
}

fn as_json(bytes: Vec<u8>) -> serde_json::Value {
    serde_json::from_slice(&bytes).expect("json decode")
}

#[derive(Default)]
struct MockProvider;

static STORE: once_cell::sync::Lazy<Mutex<HashMap<String, Vec<u8>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

impl MockProvider {
    fn describe() -> Vec<u8> {
        json_bytes(json!({
            "provider_type": "secrets",
            "capabilities": ["put", "get", "delete"]
        }))
    }

    fn validate_config(_bytes: Vec<u8>) -> Vec<u8> {
        json_bytes(json!({"status": "ok"}))
    }

    fn invoke(op: String, payload: Vec<u8>) -> Vec<u8> {
        match op.as_str() {
            "put" => {
                let value: serde_json::Value = as_json(payload);
                let key = value
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let val = value
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                STORE
                    .lock()
                    .expect("store")
                    .insert(key.to_string(), val.as_bytes().to_vec());
                json_bytes(json!({"status": "ok"}))
            }
            "get" => {
                let value: serde_json::Value = as_json(payload);
                let key = value
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let store = STORE.lock().expect("store");
                match store.get(key) {
                    Some(val) => json_bytes(json!({
                        "status": "ok",
                        "value": base64::engine::general_purpose::STANDARD.encode(val)
                    })),
                    None => json_bytes(json!({"status": "not_found"})),
                }
            }
            "delete" => {
                let value: serde_json::Value = as_json(payload);
                let key = value
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                STORE.lock().expect("store").remove(key);
                json_bytes(json!({"status": "ok"}))
            }
            _ => json_bytes(json!({"status": "error", "message": "unsupported op"})),
        }
    }
}

impl Guest for MockProvider {
    fn describe() -> Vec<u8> {
        MockProvider::describe()
    }

    fn validate_config(bytes: Vec<u8>) -> Vec<u8> {
        MockProvider::validate_config(bytes)
    }

    fn invoke(op: String, payload: Vec<u8>) -> Vec<u8> {
        MockProvider::invoke(op, payload)
    }

    fn healthcheck() -> Vec<u8> {
        json_bytes(json!({"status": "ok"}))
    }
}

#[test]
fn provider_core_inmemory_roundtrip() {
    let meta = as_json(MockProvider::describe());
    assert_eq!(
        meta.get("provider_type").and_then(|v| v.as_str()),
        Some("secrets")
    );

    let validated = MockProvider::validate_config(json_bytes(json!({})));
    assert_eq!(
        as_json(validated).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let put = MockProvider::invoke(
        "put".into(),
        json_bytes(json!({"key": "k1", "value": "secret-value"})),
    );
    assert_eq!(
        as_json(put).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let get = MockProvider::invoke("get".into(), json_bytes(json!({"key": "k1"})));
    let get_json = as_json(get);
    let val_b64 = get_json
        .get("value")
        .and_then(|v| v.as_str())
        .expect("value");
    let decoded = general_purpose::STANDARD.decode(val_b64).expect("b64");
    assert_eq!(decoded, b"secret-value");

    let del = MockProvider::invoke("delete".into(), json_bytes(json!({"key": "k1"})));
    assert_eq!(
        as_json(del).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
}
