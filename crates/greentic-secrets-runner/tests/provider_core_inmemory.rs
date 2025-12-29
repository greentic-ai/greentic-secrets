use base64::{engine::general_purpose, Engine};
use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
use schema_core_api::Guest;
use secrets_provider_inmemory::InMemoryProvider;
use serde_json::json;

fn json_bytes(val: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&val).expect("json serialize")
}

fn as_json(bytes: Vec<u8>) -> serde_json::Value {
    serde_json::from_slice(&bytes).expect("json decode")
}

#[test]
fn provider_core_inmemory_roundtrip() {
    let meta = as_json(InMemoryProvider::describe());
    assert_eq!(
        meta.get("provider_type").and_then(|v| v.as_str()),
        Some("secrets")
    );

    let validated = InMemoryProvider::validate_config(json_bytes(json!({})));
    assert_eq!(
        as_json(validated).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let put = InMemoryProvider::invoke(
        "put".into(),
        json_bytes(json!({"key": "k1", "value": "secret-value"})),
    );
    assert_eq!(
        as_json(put).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let get = InMemoryProvider::invoke("get".into(), json_bytes(json!({"key": "k1"})));
    let get_json = as_json(get);
    let val_b64 = get_json
        .get("value")
        .and_then(|v| v.as_str())
        .expect("value");
    let decoded = general_purpose::STANDARD.decode(val_b64).expect("b64");
    assert_eq!(decoded, b"secret-value");

    let del = InMemoryProvider::invoke("delete".into(), json_bytes(json!({"key": "k1"})));
    assert_eq!(
        as_json(del).get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
}
