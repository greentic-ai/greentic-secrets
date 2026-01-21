(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"plan\": {\"config_patch\": {\"environment\": \"dev\", \"region\": \"placeholder\", \"audit\": {\"sink_type\": \"splunk\", \"sink_config_ref\": \"placeholder\"}}, \"secrets_patch\": {\"set\": {\"api_token\": {\"redacted\": true, \"value\": null}}, \"delete\": []}, \"webhook_ops\": [], \"subscription_ops\": [], \"oauth_ops\": [], \"notes\": []}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 306)
  )
)
