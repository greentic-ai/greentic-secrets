# Validation Diagnostics

## Secrets pack validators

| Code | Severity | Description |
| --- | --- | --- |
| `SEC_REQUIREMENTS_NOT_DISCOVERABLE` | Warn | Secret requirements are implied but not referenced in the manifest metadata. |
| `SEC_REQ_PARSE_NEEDS_PACK_ACCESS` | Info | Secret requirements parse checks need pack file bytes. |
| `SEC_REQ_MISSING_KEY` | Error | Secret requirement is missing a key/name. |
| `SEC_REQ_NOT_SENSITIVE` | Error | Secret requirement is not marked sensitive when sensitivity is not implicit. |
| `SEC_REQ_EXPLICITLY_NOT_SENSITIVE` | Error | Secret requirement explicitly declares non-sensitive data. |
| `SEC_BAD_KEY_FORMAT` | Warn | Secret requirement key format is not UPPER_SNAKE or greentic:// URI. |
