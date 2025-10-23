use secrets_core::SecretUri;

#[test]
fn round_trip_uri_parsing() {
    let raw = "secrets://prod/tenant/payments/configs/api-key";
    let uri = SecretUri::try_from(raw).expect("parse");
    assert_eq!(uri.to_string(), raw);

    let rehydrated = SecretUri::try_from(uri.to_string()).expect("reparse");
    assert_eq!(uri, rehydrated);
}

#[test]
fn normalises_team_placeholder() {
    let raw = "secrets://prod/tenant/_/configs/service";
    let uri = SecretUri::try_from(raw).expect("parse");
    assert!(uri.scope().team().is_none());
}
