use std::sync::Arc;

use async_nats::{Client, HeaderMap, Message, Subscriber};
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::auth::{Action, AuthContext, extract_bearer_token};
use crate::error::{AppError, AppErrorKind};
use crate::models::{
    DeleteCommand, DeleteResponse, ErrorResponse, GetCommand, ListCommand, ListItem,
    ListSecretsResponse, PutCommand, RotateCommand, RotateResponse, SecretResponse,
};
use crate::path::{build_scope, build_uri, split_prefix};
use crate::rotate;
use crate::state::AppState;
use crate::telemetry::{CORRELATION_ID_HEADER, CorrelationId, request_span};
use secrets_core::types::SecretMeta;
use uuid::Uuid;

pub async fn run(client: Client, state: AppState) -> anyhow::Result<()> {
    let client = Arc::new(client);

    let put = client.subscribe("secrets.put.req.>").await?;
    let get = client.subscribe("secrets.get.req.>").await?;
    let list = client.subscribe("secrets.list.req.>").await?;
    let del = client.subscribe("secrets.del.req.>").await?;
    let rotate = client.subscribe("secrets.rotate.req.>").await?;

    let tasks = vec![
        spawn_handler(client.clone(), "nats.put", put, state.clone(), handle_put),
        spawn_handler(client.clone(), "nats.get", get, state.clone(), handle_get),
        spawn_handler(
            client.clone(),
            "nats.list",
            list,
            state.clone(),
            handle_list,
        ),
        spawn_handler(
            client.clone(),
            "nats.delete",
            del,
            state.clone(),
            handle_delete,
        ),
        spawn_handler(client, "nats.rotate", rotate, state, handle_rotate),
    ];

    futures::future::try_join_all(tasks).await?;
    Ok(())
}

type HandlerFn = fn(Arc<Client>, AppState, SubjectParts, Message, CorrelationId) -> HandlerFuture;

type HandlerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send>>;

fn spawn_handler(
    client: Arc<Client>,
    span_name: &'static str,
    mut subscriber: Subscriber,
    state: AppState,
    handler: HandlerFn,
) -> JoinHandle<anyhow::Result<()>> {
    let span_name = span_name.to_string();
    tokio::spawn(async move {
        while let Some(message) = subscriber.next().await {
            let correlation = extract_correlation(&message);
            let span = request_span(&span_name, &correlation.0);
            let subject = match SubjectParts::try_from(message.subject.as_str()) {
                Ok(parts) => parts,
                Err(err) => {
                    send_bad_subject(client.as_ref(), &message, &correlation, err).await?;
                    continue;
                }
            };

            let msg_clone = message.clone();
            let fut = handler(
                client.clone(),
                state.clone(),
                subject,
                msg_clone,
                correlation.clone(),
            );
            if let Err(err) = fut.instrument(span).await {
                respond_error(client.as_ref(), &message, correlation.clone(), err).await?;
            }
        }
        Ok(())
    })
}

fn handle_put(
    client: Arc<Client>,
    state: AppState,
    subject: SubjectParts,
    message: Message,
    correlation: CorrelationId,
) -> HandlerFuture {
    Box::pin(async move {
        let payload = parse_put_command(&message.payload)?;
        let header_token = token_from_headers(&message);
        let payload_token = payload.token.clone();
        let token = header_token.as_deref().or(payload_token.as_deref());
        let auth = state
            .authorizer
            .authenticate_nats(message.subject.as_str(), token)
            .await?;
        state
            .authorizer
            .authorize(&auth, Action::Put, &subject.tenant, subject.team.as_deref())?;
        let response = process_put(state, &subject, payload).await?;
        respond(client.as_ref(), &message, &response, &correlation).await
    })
}

fn handle_get(
    client: Arc<Client>,
    state: AppState,
    subject: SubjectParts,
    message: Message,
    correlation: CorrelationId,
) -> HandlerFuture {
    Box::pin(async move {
        let payload = parse_get_command(&message.payload)?;
        let header_token = token_from_headers(&message);
        let payload_token = payload.token.clone();
        let token = header_token.as_deref().or(payload_token.as_deref());
        let auth = state
            .authorizer
            .authenticate_nats(message.subject.as_str(), token)
            .await?;
        state
            .authorizer
            .authorize(&auth, Action::Get, &subject.tenant, subject.team.as_deref())?;
        let response = process_get(state, &subject, payload).await?;
        respond(client.as_ref(), &message, &response, &correlation).await
    })
}

fn handle_list(
    client: Arc<Client>,
    state: AppState,
    subject: SubjectParts,
    message: Message,
    correlation: CorrelationId,
) -> HandlerFuture {
    Box::pin(async move {
        let payload = parse_list_command(&message.payload)?;
        let header_token = token_from_headers(&message);
        let payload_token = payload.token.clone();
        let token = header_token.as_deref().or(payload_token.as_deref());
        let auth = state
            .authorizer
            .authenticate_nats(message.subject.as_str(), token)
            .await?;
        state.authorizer.authorize(
            &auth,
            Action::List,
            &subject.tenant,
            subject.team.as_deref(),
        )?;
        let response = process_list(state, &subject, payload).await?;
        respond(client.as_ref(), &message, &response, &correlation).await
    })
}

fn handle_delete(
    client: Arc<Client>,
    state: AppState,
    subject: SubjectParts,
    message: Message,
    correlation: CorrelationId,
) -> HandlerFuture {
    Box::pin(async move {
        let payload = parse_delete_command(&message.payload)?;
        let header_token = token_from_headers(&message);
        let payload_token = payload.token.clone();
        let token = header_token.as_deref().or(payload_token.as_deref());
        let auth = state
            .authorizer
            .authenticate_nats(message.subject.as_str(), token)
            .await?;
        state.authorizer.authorize(
            &auth,
            Action::Delete,
            &subject.tenant,
            subject.team.as_deref(),
        )?;
        let response = process_delete(state, &subject, payload).await?;
        respond(client.as_ref(), &message, &response, &correlation).await
    })
}

fn handle_rotate(
    client: Arc<Client>,
    state: AppState,
    subject: SubjectParts,
    message: Message,
    correlation: CorrelationId,
) -> HandlerFuture {
    Box::pin(async move {
        let payload = parse_rotate_command(&message.payload)?;
        let header_token = token_from_headers(&message);
        let payload_token = payload.token.clone();
        let token = header_token.as_deref().or(payload_token.as_deref());
        let auth = state
            .authorizer
            .authenticate_nats(message.subject.as_str(), token)
            .await?;
        state.authorizer.authorize(
            &auth,
            Action::Rotate,
            &subject.tenant,
            subject.team.as_deref(),
        )?;
        let category = extract_category(message.subject.as_str())?;
        let response =
            process_rotate(state, &subject, &category, payload, &auth, &correlation).await?;
        respond(client.as_ref(), &message, &response, &correlation).await
    })
}

fn extract_correlation(message: &Message) -> CorrelationId {
    if let Some(headers) = &message.headers {
        if let Some(value) = headers.get(CORRELATION_ID_HEADER) {
            return CorrelationId(value.as_str().to_string());
        }
    }
    CorrelationId(Uuid::new_v4().to_string())
}

fn extract_category(subject: &str) -> Result<String, AppError> {
    let segments: Vec<&str> = subject.split('.').collect();
    if segments.len() < 7 {
        return Err(AppError::new(AppErrorKind::BadRequest(
            "rotate subject missing category".into(),
        )));
    }
    Ok(segments[6].to_string())
}

async fn send_bad_subject(
    client: &Client,
    message: &Message,
    correlation: &CorrelationId,
    err: String,
) -> anyhow::Result<()> {
    if let Some(reply) = &message.reply {
        let body = json!({
            "error": "bad_subject",
            "message": err,
            "correlation_id": correlation.0,
        });
        let bytes = serde_json::to_vec(&body)?;
        let mut headers = HeaderMap::new();
        headers.insert(CORRELATION_ID_HEADER, correlation.0.clone());
        let _ = client
            .publish_with_headers(reply.clone(), headers, bytes.into())
            .await;
    }
    Ok(())
}

async fn respond<T: Serialize>(
    client: &Client,
    message: &Message,
    payload: &T,
    correlation: &CorrelationId,
) -> Result<(), AppError> {
    if let Some(reply) = &message.reply {
        let bytes = marshal_response(payload, correlation)?;
        let mut headers = HeaderMap::new();
        headers.insert(CORRELATION_ID_HEADER, correlation.0.clone());
        client
            .publish_with_headers(reply.clone(), headers, bytes.into())
            .await
            .map_err(|err| AppError::new(AppErrorKind::Internal(err.to_string())))?;
    }
    Ok(())
}

async fn respond_error(
    client: &Client,
    message: &Message,
    correlation: CorrelationId,
    err: AppError,
) -> anyhow::Result<()> {
    if let Some(reply) = &message.reply {
        let body = ErrorResponse {
            error: format!("{err}"),
            message: err.to_string(),
            correlation_id: correlation.0.clone(),
        };
        let bytes = serde_json::to_vec(&body)?;
        let mut headers = HeaderMap::new();
        headers.insert(CORRELATION_ID_HEADER, correlation.0.clone());
        let _ = client
            .publish_with_headers(reply.clone(), headers, bytes.into())
            .await;
    }
    Ok(())
}

#[derive(Clone)]
struct SubjectParts {
    tenant: String,
    env: String,
    team: Option<String>,
}

impl TryFrom<&str> for SubjectParts {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let segments: Vec<&str> = value.split('.').collect();
        if segments.len() < 6 {
            return Err("subject missing segments".into());
        }
        if segments[0] != "secrets" || segments[2] != "req" {
            return Err("subject does not match secrets.*.req".into());
        }
        Ok(Self {
            tenant: segments[3].to_string(),
            env: segments[4].to_string(),
            team: match segments[5] {
                "_" => None,
                other => Some(other.to_string()),
            },
        })
    }
}

fn parse_subject(value: &str) -> Result<SubjectParts, AppError> {
    SubjectParts::try_from(value).map_err(|err| AppError::new(AppErrorKind::BadRequest(err)))
}

fn parse_put_command(bytes: &[u8]) -> Result<PutCommand, AppError> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::from(secrets_core::Error::InvalidCharacters {
            field: "payload",
            value: err.to_string(),
        })
    })
}

fn parse_get_command(bytes: &[u8]) -> Result<GetCommand, AppError> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::from(secrets_core::Error::InvalidCharacters {
            field: "payload",
            value: err.to_string(),
        })
    })
}

fn parse_list_command(bytes: &[u8]) -> Result<ListCommand, AppError> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::from(secrets_core::Error::InvalidCharacters {
            field: "payload",
            value: err.to_string(),
        })
    })
}

fn parse_delete_command(bytes: &[u8]) -> Result<DeleteCommand, AppError> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::from(secrets_core::Error::InvalidCharacters {
            field: "payload",
            value: err.to_string(),
        })
    })
}

fn parse_rotate_command(bytes: &[u8]) -> Result<RotateCommand, AppError> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::from(secrets_core::Error::InvalidCharacters {
            field: "payload",
            value: err.to_string(),
        })
    })
}

fn scope_from_subject(parts: &SubjectParts) -> Result<secrets_core::Scope, AppError> {
    build_scope(&parts.env, &parts.tenant, parts.team.as_deref())
}

async fn process_put(
    state: AppState,
    subject: &SubjectParts,
    command: PutCommand,
) -> Result<SecretResponse, AppError> {
    let scope = scope_from_subject(subject)?;
    let uri = build_uri(scope.clone(), &command.category, &command.name)?;
    let (bytes, _encoding, content_type, visibility, description) = command.body.into_bytes()?;
    let mut meta = SecretMeta::new(uri.clone(), visibility, content_type);
    meta.description = description;

    let mut broker = state.broker.lock().await;
    let version = broker
        .put_secret(meta.clone(), &bytes)
        .map_err(AppError::from)?;
    Ok(SecretResponse::from_meta(&meta, version.version, &bytes))
}

async fn process_get(
    state: AppState,
    subject: &SubjectParts,
    command: GetCommand,
) -> Result<SecretResponse, AppError> {
    let scope = scope_from_subject(subject)?;
    let uri = build_uri(scope.clone(), &command.category, &command.name)?;

    let mut broker = state.broker.lock().await;
    let data = match command.version {
        Some(version) => broker
            .get_secret_version(&uri, Some(version))
            .map_err(AppError::from)?,
        None => broker.get_secret(&uri).map_err(AppError::from)?,
    };

    match data {
        Some(secret) => Ok(SecretResponse::from_meta(
            &secret.meta,
            secret.version,
            &secret.payload,
        )),
        None => Err(AppError::new(AppErrorKind::NotFound)),
    }
}

async fn process_list(
    state: AppState,
    subject: &SubjectParts,
    command: ListCommand,
) -> Result<ListSecretsResponse, AppError> {
    let scope = scope_from_subject(subject)?;
    let (category, name) = split_prefix(command.prefix.as_deref());

    let broker = state.broker.lock().await;
    let items = broker
        .list_secrets(&scope, category, name)
        .map_err(AppError::from)?
        .into_iter()
        .map(ListItem::from)
        .collect();
    Ok(ListSecretsResponse { items })
}

async fn process_delete(
    state: AppState,
    subject: &SubjectParts,
    command: DeleteCommand,
) -> Result<DeleteResponse, AppError> {
    let scope = scope_from_subject(subject)?;
    let uri = build_uri(scope, &command.category, &command.name)?;

    let broker = state.broker.lock().await;
    let version = broker.delete_secret(&uri).map_err(AppError::from)?;
    Ok(DeleteResponse {
        version: version.version,
        deleted: true,
    })
}

async fn process_rotate(
    state: AppState,
    subject: &SubjectParts,
    category: &str,
    command: RotateCommand,
    auth: &AuthContext,
    correlation: &CorrelationId,
) -> Result<RotateResponse, AppError> {
    let scope = scope_from_subject(subject)?;
    let job_id = command.job_id.unwrap_or_else(|| correlation.0.clone());
    rotate::execute_rotation(state, scope, category, job_id, &auth.actor).await
}

fn marshal_response<T: Serialize>(
    payload: &T,
    correlation: &CorrelationId,
) -> Result<Vec<u8>, AppError> {
    let mut body = serde_json::to_value(payload)
        .map_err(|err| AppError::new(AppErrorKind::Internal(err.to_string())))?;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "correlation_id".into(),
            serde_json::Value::String(correlation.0.clone()),
        );
    }
    serde_json::to_vec(&body).map_err(|err| AppError::new(AppErrorKind::Internal(err.to_string())))
}

fn token_from_headers(message: &Message) -> Option<String> {
    let headers = message.headers.as_ref()?;
    headers
        .get("Authorization")
        .and_then(|value| extract_bearer_token(value.as_str()).map(|token| token.to_string()))
        .or_else(|| {
            headers.get("authorization").and_then(|value| {
                extract_bearer_token(value.as_str()).map(|token| token.to_string())
            })
        })
}

pub async fn execute_put(
    state: AppState,
    subject: &str,
    payload: &[u8],
) -> Result<SecretResponse, AppError> {
    let parts = parse_subject(subject)?;
    let command = parse_put_command(payload)?;
    let cmd_token = command.token.clone();
    let auth = state
        .authorizer
        .authenticate_nats(subject, cmd_token.as_deref())
        .await?;
    state
        .authorizer
        .authorize(&auth, Action::Put, &parts.tenant, parts.team.as_deref())?;
    process_put(state, &parts, command).await
}

pub async fn execute_get(
    state: AppState,
    subject: &str,
    payload: &[u8],
) -> Result<SecretResponse, AppError> {
    let parts = parse_subject(subject)?;
    let command = parse_get_command(payload)?;
    let cmd_token = command.token.clone();
    let auth = state
        .authorizer
        .authenticate_nats(subject, cmd_token.as_deref())
        .await?;
    state
        .authorizer
        .authorize(&auth, Action::Get, &parts.tenant, parts.team.as_deref())?;
    process_get(state, &parts, command).await
}

pub async fn execute_list(
    state: AppState,
    subject: &str,
    payload: &[u8],
) -> Result<ListSecretsResponse, AppError> {
    let parts = parse_subject(subject)?;
    let command = parse_list_command(payload)?;
    let cmd_token = command.token.clone();
    let auth = state
        .authorizer
        .authenticate_nats(subject, cmd_token.as_deref())
        .await?;
    state
        .authorizer
        .authorize(&auth, Action::List, &parts.tenant, parts.team.as_deref())?;
    process_list(state, &parts, command).await
}

pub async fn execute_delete(
    state: AppState,
    subject: &str,
    payload: &[u8],
) -> Result<DeleteResponse, AppError> {
    let parts = parse_subject(subject)?;
    let command = parse_delete_command(payload)?;
    let cmd_token = command.token.clone();
    let auth = state
        .authorizer
        .authenticate_nats(subject, cmd_token.as_deref())
        .await?;
    state
        .authorizer
        .authorize(&auth, Action::Delete, &parts.tenant, parts.team.as_deref())?;
    process_delete(state, &parts, command).await
}

pub fn serialize_payload_with_correlation<T: Serialize>(
    payload: &T,
    correlation: &CorrelationId,
) -> Result<Vec<u8>, AppError> {
    marshal_response(payload, correlation)
}
