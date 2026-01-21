(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"requirements\": {\"provider_id\": \"greentic.secrets.fixture\", \"config\": {\"required\": [\"environment\", \"region\", \"audit\"], \"optional\": [], \"constraints\": {\"enum\": {\"environment\": [\"dev\", \"stage\"]}}}, \"secrets\": {\"required\": [\"api_token\"], \"optional\": [], \"constraints\": {}}, \"capabilities\": {\"supports_read\": true, \"supports_write\": true, \"supports_delete\": true}, \"setup_needs\": {\"public_base_url\": false, \"oauth\": false, \"subscriptions\": false}}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 445)
  )
)
