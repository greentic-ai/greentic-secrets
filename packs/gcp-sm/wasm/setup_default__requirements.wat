(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"requirements\":{\"provider_id\":\"greentic.secrets.gcp-sm\",\"config\":{\"required\":[\"tenant_id\",\"environment\",\"project_id\",\"auth_mode\",\"namespace_prefix\",\"audit\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"optional\":[\"location\",\"labels\"],\"constraints\":{\"enum\":{\"environment\":[\"dev\",\"stage\",\"prod\"],\"auth_mode\":[\"workload_identity\",\"service_account_json\"]}}},\"secrets\":{\"required\":[\"audit_sink_credentials\"],\"optional\":[\"gcp_service_account_json\"],\"constraints\":{}},\"capabilities\":{\"supports_read\":true,\"supports_write\":true,\"supports_delete\":true},\"setup_needs\":{\"public_base_url\":false,\"oauth\":false,\"subscriptions\":false}}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 623)
  )
)
