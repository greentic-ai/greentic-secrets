use axum::body::Body;
use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::global;
use tracing::{info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

pub const CORRELATION_ID_HEADER: &str = "x-correlation-id";

#[derive(Clone, Debug)]
pub struct CorrelationId(pub String);

pub fn init() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    let _ = global::tracer("greentic::secrets");

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(false),
        )
        .try_init()
        .ok();

    Ok(())
}

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
