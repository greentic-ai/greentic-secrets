(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"requirements\":{\"provider_id\":\"greentic.secrets.azure-kv\",\"config\":{\"required\":[\"tenant_id\",\"environment\",\"vault_url\",\"auth_mode\",\"namespace_prefix\",\"audit\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"optional\":[\"client_id\",\"labels\"],\"constraints\":{\"enum\":{\"environment\":[\"dev\",\"stage\",\"prod\"],\"auth_mode\":[\"managed_identity\",\"service_principal\",\"device_code\"]}}},\"secrets\":{\"required\":[\"audit_sink_credentials\"],\"optional\":[\"azure_client_secret\"],\"constraints\":{}},\"capabilities\":{\"supports_read\":true,\"supports_write\":true,\"supports_delete\":true},\"setup_needs\":{\"public_base_url\":false,\"oauth\":false,\"subscriptions\":false}}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 630)
  )
)
