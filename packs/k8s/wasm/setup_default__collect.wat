(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"questions\":{\"config_required\":[\"tenant_id\",\"environment\",\"namespace\",\"auth_mode\",\"namespace_prefix\",\"audit\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"secrets_required\":[\"audit_sink_credentials\"]}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 203)
  )
)
