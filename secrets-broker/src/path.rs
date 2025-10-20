use crate::error::{AppError, AppErrorKind};
use secrets_core::{Scope, SecretUri};

pub fn build_scope(env: &str, tenant: &str, team: Option<&str>) -> Result<Scope, AppError> {
    let normalized = team.and_then(|value| match value {
        "_" => None,
        "" => None,
        other => Some(other.to_string()),
    });
    Scope::new(env.to_string(), tenant.to_string(), normalized).map_err(AppError::from)
}

pub fn build_uri(scope: Scope, category: &str, name: &str) -> Result<SecretUri, AppError> {
    SecretUri::new(scope, category.to_string(), name.to_string()).map_err(AppError::from)
}

pub fn split_name_version(input: &str) -> Result<(String, Option<u64>), AppError> {
    if let Some((name, version)) = input.rsplit_once('@') {
        if version.is_empty() {
            return Err(AppError::new(AppErrorKind::BadRequest(
                "version missing".into(),
            )));
        }
        let parsed = version
            .parse::<u64>()
            .map_err(|_| AppError::new(AppErrorKind::BadRequest("invalid version".into())))?;
        Ok((name.to_string(), Some(parsed)))
    } else {
        Ok((input.to_string(), None))
    }
}

pub fn split_prefix(prefix: Option<&str>) -> (Option<&str>, Option<&str>) {
    prefix.map_or((None, None), |value| {
        let mut parts = value.splitn(2, '/');
        let category = parts.next().filter(|s| !s.is_empty());
        let name = parts.next().filter(|s| !s.is_empty());
        (category, name)
    })
}
