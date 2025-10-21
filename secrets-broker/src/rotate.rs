use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;
use crate::models::RotateResponse;
use crate::state::AppState;
use secrets_core::backend::SecretsBackend;
use secrets_core::key_provider::KeyProvider;
use secrets_core::types::{Scope, SecretListItem};
use secrets_core::{SecretUri, SecretsBroker};
use tracing::{debug, error, info};

const TAG_LAST_JOB: &str = "rotation.last_job";
const TAG_LAST_TS: &str = "rotation.last_ts";

/// Execute a rotation job for the provided scope and category.
pub async fn execute_rotation(
    state: AppState,
    scope: Scope,
    category: &str,
    job_id: String,
    actor: &str,
) -> Result<RotateResponse, AppError> {
    let mut broker = state.broker.lock().await;
    let items = broker
        .list_secrets(&scope, Some(category), None)
        .map_err(AppError::from)?;

    info!(
        target = "audit",
        action = "rotation.start",
        job_id = %job_id,
        category = %category,
        env = %scope.env(),
        tenant = %scope.tenant(),
        team = %scope.team().unwrap_or("_"),
        actor = %actor,
        total = items.len(),
        "rotation job starting"
    );

    let mut rotated = 0usize;
    let mut skipped = 0usize;

    for item in items {
        if item.uri.category() != category {
            continue;
        }
        match rotate_secret(&mut broker, &item, &job_id)? {
            RotationResult::Rotated => rotated += 1,
            RotationResult::Skipped => skipped += 1,
        }
        debug!(
            target = "metrics",
            action = "rotation.progress",
            job_id = %job_id,
            category = %category,
            env = %scope.env(),
            tenant = %scope.tenant(),
            team = %scope.team().unwrap_or("_"),
            rotated = rotated,
            skipped = skipped,
            secret = %item.uri.name(),
            "rotation progress"
        );
    }

    info!(
        target = "audit",
        action = "rotation.finish",
        job_id = %job_id,
        category = %category,
        env = %scope.env(),
        tenant = %scope.tenant(),
        team = %scope.team().unwrap_or("_"),
        actor = %actor,
        rotated = rotated,
        skipped = skipped,
        "rotation job completed"
    );

    Ok(RotateResponse {
        job_id,
        category: category.to_string(),
        rotated,
        skipped,
    })
}

enum RotationResult {
    Rotated,
    Skipped,
}

fn rotate_secret(
    broker: &mut SecretsBroker<Box<dyn SecretsBackend>, Box<dyn KeyProvider>>,
    item: &SecretListItem,
    job_id: &str,
) -> Result<RotationResult, AppError> {
    let uri: SecretUri = item.uri.clone();
    let secret = match broker.get_secret(&uri).map_err(AppError::from)? {
        Some(value) => value,
        None => return Ok(RotationResult::Skipped),
    };

    if secret
        .meta
        .tags()
        .get(TAG_LAST_JOB)
        .map(|value| value == job_id)
        .unwrap_or(false)
    {
        return Ok(RotationResult::Skipped);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    let mut meta = secret.meta.clone();
    meta.set_tag(TAG_LAST_JOB, job_id.to_string());
    meta.set_tag(TAG_LAST_TS, now);

    broker.put_secret(meta, &secret.payload).map_err(|err| {
        let app_err = AppError::from(err);
        error!(
            target = "audit",
            action = "rotation.error",
            job_id = %job_id,
            uri = %uri,
            error = %app_err,
            "failed to store rotated secret"
        );
        app_err
    })?;

    Ok(RotationResult::Rotated)
}
