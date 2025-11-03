use axum::body::Body;
use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use greentic_types::telemetry::set_current_tenant_ctx;
use greentic_types::{EnvId, TeamId, TenantCtx, TenantId, UserId};
use tracing::{Span, info_span};
use uuid::Uuid;

use crate::auth::AuthContext;

pub const CORRELATION_ID_HEADER: &str = "x-correlation-id";

#[derive(Clone, Debug)]
pub struct CorrelationId(pub String);

pub fn correlation_header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("correlation id header")
}

pub async fn correlation_layer(mut req: Request<Body>, next: Next) -> Response {
    let header_value = req
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut()
        .insert(CorrelationId(header_value.clone()));
    req.headers_mut().insert(
        CORRELATION_ID_HEADER,
        correlation_header_value(&header_value),
    );

    let span = info_span!(
        "request",
        method = %req.method(),
        uri = %req.uri(),
        correlation_id = %header_value
    );
    let _enter = span.enter();

    let mut response = next.run(req).await;
    response.headers_mut().insert(
        CORRELATION_ID_HEADER,
        correlation_header_value(&header_value),
    );
    response
}

pub fn request_span(name: &str, correlation_id: &str) -> Span {
    info_span!(
        "broker.op",
        operation = name,
        correlation_id = %correlation_id
    )
}

pub fn set_tenant_context(
    env: &str,
    tenant: &str,
    team: Option<&str>,
    correlation: &CorrelationId,
    auth: Option<&AuthContext>,
) {
    let mut ctx =
        TenantCtx::new(EnvId::from(env), TenantId::from(tenant)).with_provider("secrets-broker");
    let team_value = team
        .map(|value| value.to_string())
        .or_else(|| auth.and_then(|ctx| ctx.team.clone()));
    ctx = ctx.with_team(team_value.map(TeamId::from));
    if let Some(auth_ctx) = auth {
        ctx = ctx.with_user(Some(UserId::from(auth_ctx.subject.as_str())));
    }
    let mut final_ctx = ctx;
    final_ctx.correlation_id = Some(correlation.0.clone());
    set_current_tenant_ctx(&final_ctx);
}
