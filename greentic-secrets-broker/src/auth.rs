use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::AppError;
use crate::state::AppState;

const TENANT_ADMIN_ROLES: &[&str] = &["admin", "platform-admin", "tenant-admin"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Action {
    Put = 0,
    Get = 1,
    Delete = 2,
    Rotate = 3,
    List = 4,
}

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub subject: String,
    pub tenant: String,
    pub team: Option<String>,
    pub roles: Vec<String>,
    pub actor: String,
    permissions: Permissions,
}

impl AuthContext {
    fn new(claims: Claims, permissions: Permissions) -> Self {
        Self {
            subject: claims.sub,
            tenant: claims.tenant,
            team: claims.team.filter(|value| !value.is_empty()),
            roles: claims.roles,
            actor: claims.actor,
            permissions,
        }
    }

    pub fn allows(&self, action: Action) -> bool {
        self.permissions.allows(action)
    }
}

#[derive(Clone, Copy, Debug)]
struct Permissions(u8);

impl Permissions {
    const fn empty() -> Self {
        Permissions(0)
    }

    const fn all() -> Self {
        Permissions((1 << 5) - 1)
    }

    fn from_action(action: Action) -> Self {
        Permissions(1 << (action as u8))
    }

    fn union(self, other: Self) -> Self {
        Permissions(self.0 | other.0)
    }

    fn allows(self, action: Action) -> bool {
        (self.0 & (1 << (action as u8))) != 0
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Permissions::empty()
    }
}

#[derive(Clone)]
pub struct Authorizer {
    issuer: String,
    audience: String,
    key_provider: KeyProvider,
    internal_subjects: Vec<SubjectMatcher>,
    internal_context: Option<Arc<AuthContext>>,
}

#[derive(Clone)]
enum KeyProvider {
    Static(Arc<Vec<u8>>),
    Jwks {
        url: String,
        client: HttpClient,
        cache: Arc<RwLock<HashMap<String, Arc<Vec<u8>>>>>,
    },
}

#[derive(Clone)]
struct SubjectMatcher {
    prefix: String,
}

impl SubjectMatcher {
    fn matches(&self, subject: &str) -> bool {
        subject.starts_with(&self.prefix)
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeaderParts {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    tenant: String,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    actor: String,
    #[allow(dead_code)]
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    _alg: Option<String>,
    #[serde(default)]
    x: Option<String>,
}

impl Authorizer {
    pub async fn from_env() -> anyhow::Result<Self> {
        let issuer = std::env::var("AUTH_JWT_ISS").context("AUTH_JWT_ISS is required")?;
        let audience = std::env::var("AUTH_JWT_AUD").context("AUTH_JWT_AUD is required")?;
        let jwks_url = std::env::var("AUTH_JWT_JWKS_URL").ok();
        let ed25519 = std::env::var("AUTH_JWT_ED25519_PUB").ok();

        let key_provider = match (jwks_url, ed25519) {
            (Some(url), None) => {
                let client = HttpClient::builder()
                    .build()
                    .context("failed to build reqwest client")?;
                KeyProvider::Jwks {
                    url,
                    client,
                    cache: Arc::new(RwLock::new(HashMap::new())),
                }
            }
            (None, Some(key)) => {
                let raw = decode_ed25519_key(&key)
                    .map_err(|err| anyhow!("failed to decode AUTH_JWT_ED25519_PUB: {err}"))?;
                KeyProvider::Static(Arc::new(raw))
            }
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "only one of AUTH_JWT_JWKS_URL or AUTH_JWT_ED25519_PUB may be set"
                ));
            }
            (None, None) => {
                return Err(anyhow!(
                    "AUTH_JWT_JWKS_URL or AUTH_JWT_ED25519_PUB must be configured"
                ));
            }
        };

        let internal_subjects = std::env::var("AUTH_JWT_INTERNAL_SUBJECTS")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .split(',')
                    .map(|segment| SubjectMatcher {
                        prefix: segment.trim().to_string(),
                    })
                    .filter(|matcher| !matcher.prefix.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let mut authorizer = Self {
            issuer,
            audience,
            key_provider,
            internal_subjects,
            internal_context: None,
        };

        if !authorizer.internal_subjects.is_empty() {
            match std::env::var("AUTH_JWT_INTERNAL_TOKEN") {
                Ok(token) => {
                    let context = authorizer
                        .authenticate(&token)
                        .await
                        .context("failed to validate AUTH_JWT_INTERNAL_TOKEN")?;
                    authorizer.internal_context = Some(Arc::new(context));
                }
                Err(_) => {
                    warn!(
                        "AUTH_JWT_INTERNAL_SUBJECTS configured without AUTH_JWT_INTERNAL_TOKEN; \
                         subject allow list will still require tokens from callers"
                    );
                }
            }
        }

        Ok(authorizer)
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthContext, AppError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AppError::unauthorized("missing authorization token"));
        }

        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(AppError::unauthorized("invalid token format"));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(segments[0].as_bytes())
            .map_err(|_| AppError::unauthorized("invalid token header"))?;
        let header: JwtHeaderParts = serde_json::from_slice(&header_bytes)
            .map_err(|_| AppError::unauthorized("invalid token header"))?;
        if header.alg != "EdDSA" {
            return Err(AppError::unauthorized("unsupported signing algorithm"));
        }

        let key_bytes = self.lookup_public_key(&header).await?;
        let signing_input = format!(
            "{header}.{payload}",
            header = segments[0],
            payload = segments[1]
        );
        let signature = URL_SAFE_NO_PAD
            .decode(segments[2].as_bytes())
            .map_err(|_| AppError::unauthorized("invalid token signature"))?;

        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key_bytes.as_ref())
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| AppError::unauthorized("token validation error"))?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(segments[1].as_bytes())
            .map_err(|_| AppError::unauthorized("invalid token payload"))?;
        let claims: Claims = serde_json::from_slice(&payload_bytes)
            .map_err(|_| AppError::unauthorized("invalid token payload"))?;

        self.validate_claims(&claims)?;

        if claims.roles.is_empty() {
            return Err(AppError::forbidden("token missing roles"));
        }

        let permissions = permissions_for_roles(&claims.roles);
        if permissions.0 == 0 {
            return Err(AppError::forbidden("token roles do not allow any actions"));
        }

        Ok(AuthContext::new(claims, permissions))
    }

    pub async fn authenticate_nats(
        &self,
        subject: &str,
        token: Option<&str>,
    ) -> Result<AuthContext, AppError> {
        if let Some(token) = token {
            return self.authenticate(token).await;
        }

        if let Some(context) = self.match_internal_subject(subject) {
            return Ok((*context).clone());
        }

        Err(AppError::unauthorized("missing authorization token"))
    }

    pub fn authorize(
        &self,
        ctx: &AuthContext,
        action: Action,
        tenant: &str,
        team: Option<&str>,
    ) -> Result<(), AppError> {
        if !ctx.allows(action) {
            return Err(AppError::forbidden("role does not permit requested action"));
        }

        if ctx.tenant != tenant {
            return Err(AppError::forbidden("token tenant mismatch"));
        }

        match (&ctx.team, team) {
            (Some(token_team), Some(request_team)) if token_team == request_team => Ok(()),
            (Some(_), Some(_)) => Err(AppError::forbidden("token team mismatch")),
            (Some(_), None) => Err(AppError::forbidden(
                "team-scoped token cannot access tenant-wide secrets",
            )),
            (None, Some(_)) => {
                if has_cross_team_role(&ctx.roles) {
                    Ok(())
                } else {
                    Err(AppError::forbidden(
                        "token not permitted to access other teams within tenant",
                    ))
                }
            }
            (None, None) => Ok(()),
        }
    }

    fn match_internal_subject(&self, subject: &str) -> Option<Arc<AuthContext>> {
        if self.internal_subjects.is_empty() {
            return None;
        }

        self.internal_subjects
            .iter()
            .any(|matcher| matcher.matches(subject))
            .then(|| self.internal_context.clone())
            .flatten()
    }

    fn validate_claims(&self, claims: &Claims) -> Result<(), AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs() as i64;
        if claims.exp < now {
            return Err(AppError::unauthorized("token expired"));
        }

        match claims.iss.as_deref() {
            Some(value) if value == self.issuer => {}
            _ => return Err(AppError::unauthorized("invalid issuer")),
        }

        match claims.aud.as_deref() {
            Some(value) if value == self.audience => {}
            _ => return Err(AppError::unauthorized("invalid audience")),
        }

        Ok(())
    }

    async fn lookup_public_key(&self, header: &JwtHeaderParts) -> Result<Arc<Vec<u8>>, AppError> {
        match &self.key_provider {
            KeyProvider::Static(key) => Ok(key.clone()),
            KeyProvider::Jwks { url, client, cache } => {
                let kid = header
                    .kid
                    .clone()
                    .ok_or_else(|| AppError::unauthorized("token missing key identifier (kid)"))?;

                if let Some(existing) = cache.read().await.get(&kid).cloned() {
                    return Ok(existing);
                }

                let jwks = client
                    .get(url)
                    .send()
                    .await
                    .map_err(|err| AppError::unauthorized(format!("failed to fetch JWKS: {err}")))?
                    .error_for_status()
                    .map_err(|err| AppError::unauthorized(format!("invalid JWKS response: {err}")))?
                    .json::<Jwks>()
                    .await
                    .map_err(|err| {
                        AppError::unauthorized(format!("failed to decode JWKS: {err}"))
                    })?;

                let mut cache_guard = cache.write().await;
                debug!(url = %url, "refreshing JWKS cache");
                for jwk in jwks.keys {
                    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
                        continue;
                    }
                    let kid_val = match jwk.kid.clone() {
                        Some(value) => value,
                        None => continue,
                    };

                    if let Some(raw) = jwk.x.as_ref() {
                        if let Ok(raw_bytes) = decode_ed25519_key(raw) {
                            cache_guard.insert(kid_val.clone(), Arc::new(raw_bytes));
                        }
                    }
                }

                cache_guard
                    .get(&kid)
                    .cloned()
                    .ok_or_else(|| AppError::unauthorized("unable to locate signing key for token"))
            }
        }
    }
}

pub fn extract_bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("Bearer ") {
        Some(rest.trim())
    } else if let Some(rest) = value.strip_prefix("bearer ") {
        Some(rest.trim())
    } else {
        None
    }
}

pub async fn http_layer(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .map(str::to_owned);

    let token = match token {
        Some(token) => token,
        None => return AppError::unauthorized("missing authorization header").into_response(),
    };

    match state.authorizer.authenticate(&token).await {
        Ok(context) => {
            req.extensions_mut().insert(context);
            next.run(req).await
        }
        Err(err) => err.into_response(),
    }
}

fn permissions_for_roles(roles: &[String]) -> Permissions {
    let mut permissions = Permissions::default();
    for role in roles {
        let role_perm = match role.as_str() {
            "admin" | "platform-admin" => Permissions::all(),
            "writer" | "service-writer" => Permissions::from_action(Action::Put)
                .union(Permissions::from_action(Action::Get))
                .union(Permissions::from_action(Action::Delete))
                .union(Permissions::from_action(Action::List)),
            "reader" | "auditor" => {
                Permissions::from_action(Action::Get).union(Permissions::from_action(Action::List))
            }
            "deleter" => Permissions::from_action(Action::Delete),
            "rotator" => Permissions::from_action(Action::Rotate),
            "lister" => Permissions::from_action(Action::List),
            _ => Permissions::empty(),
        };
        permissions = permissions.union(role_perm);
    }
    permissions
}

fn has_cross_team_role(roles: &[String]) -> bool {
    roles
        .iter()
        .any(|role| TENANT_ADMIN_ROLES.contains(&role.as_str()))
}

fn decode_ed25519_key(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes())
}
