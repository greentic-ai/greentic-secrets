use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_kms::{primitives::Blob as KmsBlob, Client as KmsClient};
use aws_sdk_secretsmanager::error::SdkError;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_types::region::Region;
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError, SecretsResult, VersionedSecret,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::runtime::Runtime;

const DEFAULT_PREFIX: &str = "gtsec";
const DEFAULT_STAGE: &str = "AWSCURRENT";
const PREFIX_ENV: &str = "GREENTIC_AWS_SECRET_PREFIX";
const STAGE_ENV: &str = "GREENTIC_AWS_VERSION_STAGE";
const KMS_KEY_ENV: &str = "GREENTIC_AWS_KMS_KEY_ID";
const REGION_ENV: &str = "GREENTIC_AWS_REGION";
const TEAM_PLACEHOLDER: &str = "_";

/// Components returned for integration with the broker/core wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Build the AWS Secrets Manager backend and corresponding KMS key provider.
pub async fn build_backend() -> Result<BackendComponents> {
    let (config, shared_config) = AwsProviderConfig::load_from_env().await?;

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .context("failed to create tokio runtime for aws backend")?,
    );

    let secrets_client = SecretsManagerClient::new(&shared_config);
    let kms_client = KmsClient::new(&shared_config);

    let backend = AwsSecretsBackend::new(secrets_client, config.clone(), runtime.clone());
    let key_provider = AwsKmsKeyProvider::new(kms_client, config.clone(), runtime);

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct AwsProviderConfig {
    secret_prefix: String,
    version_stage: String,
    kms_key_id: String,
}

impl AwsProviderConfig {
    async fn load_from_env() -> Result<(Self, aws_types::SdkConfig)> {
        let prefix = env::var(PREFIX_ENV).unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        let stage = env::var(STAGE_ENV).unwrap_or_else(|_| DEFAULT_STAGE.to_string());
        let kms_key_id = env::var(KMS_KEY_ENV)
            .context("GREENTIC_AWS_KMS_KEY_ID must be set for the AWS provider")?;
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Ok(region) = env::var(REGION_ENV) {
            loader = loader.region(Region::new(region));
        }

        let shared_config = loader.load().await;

        Ok((
            Self {
                secret_prefix: prefix,
                version_stage: stage,
                kms_key_id,
            },
            shared_config,
        ))
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}",
            self.secret_prefix,
            uri.scope().env(),
            uri.scope().tenant(),
            uri.scope().team().unwrap_or(TEAM_PLACEHOLDER),
            uri.category(),
            uri.name()
        )
    }

    fn scope_prefix(&self, scope: &Scope) -> String {
        format!("{}/{}/{}/", self.secret_prefix, scope.env(), scope.tenant())
    }
}

#[derive(Clone)]
pub struct AwsSecretsBackend {
    client: SecretsManagerClient,
    config: AwsProviderConfig,
    runtime: Arc<Runtime>,
}

impl AwsSecretsBackend {
    fn new(client: SecretsManagerClient, config: AwsProviderConfig, runtime: Arc<Runtime>) -> Self {
        Self {
            client,
            config,
            runtime,
        }
    }

    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.runtime.block_on(fut)
    }

    fn fetch_latest_version(&self, secret_id: &str) -> SecretsResult<Option<StoredSecret>> {
        self.block_on(async {
            match self
                .client
                .get_secret_value()
                .secret_id(secret_id)
                .send()
                .await
            {
                Ok(output) => {
                    deserialize_secret_payload(output.secret_string(), output.secret_binary())
                }
                Err(err) => {
                    if is_not_found(&err) {
                        Ok(None)
                    } else {
                        Err(storage_error("get_secret_value", err))
                    }
                }
            }
        })
    }

    fn fetch_version_by_id(
        &self,
        secret_id: &str,
        version_id: &str,
    ) -> SecretsResult<Option<StoredSecret>> {
        self.block_on(async {
            match self
                .client
                .get_secret_value()
                .secret_id(secret_id)
                .version_id(version_id)
                .send()
                .await
            {
                Ok(output) => {
                    deserialize_secret_payload(output.secret_string(), output.secret_binary())
                }
                Err(err) => {
                    if is_not_found(&err) {
                        Ok(None)
                    } else {
                        Err(storage_error("get_secret_value", err))
                    }
                }
            }
        })
    }

    fn load_all_versions(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let secret_id = self.config.secret_name(uri);
        self.block_on(async {
            let mut collected = Vec::new();
            let mut token: Option<String> = None;

            loop {
                let mut request = self
                    .client
                    .list_secret_version_ids()
                    .secret_id(&secret_id)
                    .include_deprecated(true);

                if let Some(ref next) = token {
                    request = request.next_token(next);
                }

                let response = match request.send().await {
                    Ok(resp) => resp,
                    Err(err) => {
                        if is_not_found(&err) {
                            return Ok(Vec::new());
                        }
                        return Err(storage_error("list_secret_version_ids", err));
                    }
                };

                for entry in response.versions() {
                    if let Some(version_id) = entry.version_id() {
                        if let Some(stored) = self.fetch_version_by_id(&secret_id, version_id)? {
                            collected.push(stored);
                        }
                    }
                }

                if let Some(next) = response.next_token() {
                    token = Some(next.to_string());
                } else {
                    break;
                }
            }

            collected.sort_by_key(|item| item.version);
            Ok(collected)
        })
    }

    fn ensure_secret_created(
        &self,
        secret_id: &str,
        payload: &str,
        record: Option<&SecretRecord>,
    ) -> SecretsResult<bool> {
        self.block_on(async {
            let mut request = self
                .client
                .create_secret()
                .name(secret_id)
                .secret_string(payload);
            if let Some(record) = record {
                if let Some(description) = record.meta.description.clone() {
                    if !description.is_empty() {
                        request = request.description(description);
                    }
                }
            }

            match request.send().await {
                Ok(_) => Ok(true),
                Err(err) => {
                    if let SdkError::ServiceError(context) = &err {
                        if context.err().is_resource_exists_exception() {
                            return Ok(false);
                        }
                    }
                    Err(storage_error("create_secret", err))
                }
            }
        })
    }

    fn write_new_version(&self, secret_id: &str, payload: &str) -> SecretsResult<()> {
        self.block_on(async {
            match self
                .client
                .put_secret_value()
                .secret_id(secret_id)
                .secret_string(payload)
                .set_version_stages(Some(vec![self.config.version_stage.clone()]))
                .send()
                .await
            {
                Ok(_) => Ok(()),
                Err(err) => Err(storage_error("put_secret_value", err)),
            }
        })
    }

    fn list_scope(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let prefix = self.config.scope_prefix(scope);

        self.block_on(async {
            let mut items = Vec::new();
            let mut token: Option<String> = None;

            loop {
                let mut request = self.client.list_secrets();
                let filter = Filter::builder()
                    .key(FilterNameStringType::Name)
                    .values(prefix.clone())
                    .build();
                request = request.filters(filter);
                if let Some(ref next) = token {
                    request = request.next_token(next);
                }

                let response = match request.send().await {
                    Ok(resp) => resp,
                    Err(err) => return Err(storage_error("list_secrets", err)),
                };

                for entry in response.secret_list() {
                    let name = match entry.name() {
                        Some(value) => value,
                        None => continue,
                    };
                    if !name.starts_with(&prefix) {
                        continue;
                    }
                    let uri = match parse_secret_name(&self.config.secret_prefix, name) {
                        Some(uri) => uri,
                        None => continue,
                    };
                    if uri.scope().env() != scope.env() || uri.scope().tenant() != scope.tenant() {
                        continue;
                    }
                    if scope.team().is_some() && uri.scope().team() != scope.team() {
                        continue;
                    }
                    if let Some(prefix) = category_prefix {
                        if !uri.category().starts_with(prefix) {
                            continue;
                        }
                    }
                    if let Some(prefix) = name_prefix {
                        if !uri.name().starts_with(prefix) {
                            continue;
                        }
                    }

                    if let Some(stored) = self.fetch_latest_version(name)? {
                        if stored.deleted {
                            continue;
                        }
                        if let Some(record) = stored.record {
                            let latest = Some(stored.version.to_string());
                            items.push(SecretListItem::from_meta(&record.meta, latest));
                        }
                    }
                }

                if let Some(next) = response.next_token() {
                    token = Some(next.to_string());
                } else {
                    break;
                }
            }

            Ok(items)
        })
    }
}

impl SecretsBackend for AwsSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let secret_id = self.config.secret_name(&record.meta.uri);

        let versions = self.load_all_versions(&record.meta.uri)?;
        let next_version = versions
            .iter()
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::live(next_version, record.clone());
        let payload = serde_json::to_string(&stored)
            .map_err(|err| SecretsError::Storage(format!("serialize secret payload: {err}")))?;

        if versions.is_empty() {
            let created = self.ensure_secret_created(&secret_id, &payload, Some(&record))?;
            if !created {
                self.write_new_version(&secret_id, &payload)?;
            }
        } else {
            self.write_new_version(&secret_id, &payload)?;
        }

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let secret_id = self.config.secret_name(uri);

        if let Some(version) = version {
            let versions = self.load_all_versions(uri)?;
            return Ok(versions
                .into_iter()
                .find(|stored| stored.version == version)
                .map(|stored| stored.into_versioned()));
        }

        match self.fetch_latest_version(&secret_id)? {
            Some(stored) if !stored.deleted => Ok(Some(stored.into_versioned())),
            _ => Ok(None),
        }
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        self.list_scope(scope, category_prefix, name_prefix)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let secret_id = self.config.secret_name(uri);
        let versions = self.load_all_versions(uri)?;
        if versions.is_empty() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions
            .iter()
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::tombstone(next_version);
        let payload = serde_json::to_string(&stored)
            .map_err(|err| SecretsError::Storage(format!("serialize tombstone payload: {err}")))?;

        self.write_new_version(&secret_id, &payload)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        Ok(self
            .load_all_versions(uri)?
            .into_iter()
            .map(|stored| SecretVersion {
                version: stored.version,
                deleted: stored.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

#[derive(Clone)]
pub struct AwsKmsKeyProvider {
    client: KmsClient,
    key_id: String,
    runtime: Arc<Runtime>,
}

impl AwsKmsKeyProvider {
    fn new(client: KmsClient, config: AwsProviderConfig, runtime: Arc<Runtime>) -> Self {
        Self {
            client,
            key_id: config.kms_key_id,
            runtime,
        }
    }

    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.runtime.block_on(fut)
    }

    fn context(scope: &Scope) -> HashMap<String, String> {
        let mut ctx = HashMap::new();
        ctx.insert("env".into(), scope.env().to_string());
        ctx.insert("tenant".into(), scope.tenant().to_string());
        if let Some(team) = scope.team() {
            ctx.insert("team".into(), team.to_string());
        }
        ctx
    }
}

impl KeyProvider for AwsKmsKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let context = Self::context(scope);
        self.block_on(async {
            match self
                .client
                .encrypt()
                .key_id(&self.key_id)
                .set_encryption_context(Some(context))
                .plaintext(KmsBlob::new(dek.to_vec()))
                .send()
                .await
            {
                Ok(output) => output
                    .ciphertext_blob()
                    .map(|blob| blob.as_ref().to_vec())
                    .ok_or_else(|| {
                        SecretsError::Backend("kms encrypt returned no ciphertext".into())
                    }),
                Err(err) => Err(SecretsError::Backend(format!("kms encrypt: {err}"))),
            }
        })
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let context = Self::context(scope);
        self.block_on(async {
            match self
                .client
                .decrypt()
                .key_id(&self.key_id)
                .set_encryption_context(Some(context))
                .ciphertext_blob(KmsBlob::new(wrapped.to_vec()))
                .send()
                .await
            {
                Ok(output) => output
                    .plaintext()
                    .map(|blob| blob.as_ref().to_vec())
                    .ok_or_else(|| {
                        SecretsError::Backend("kms decrypt returned no plaintext".into())
                    }),
                Err(err) => Err(SecretsError::Backend(format!("kms decrypt: {err}"))),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSecret {
    version: u64,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<SecretRecord>,
}

impl StoredSecret {
    fn live(version: u64, record: SecretRecord) -> Self {
        Self {
            version,
            deleted: false,
            record: Some(record),
        }
    }

    fn tombstone(version: u64) -> Self {
        Self {
            version,
            deleted: true,
            record: None,
        }
    }

    fn into_versioned(self) -> VersionedSecret {
        VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: self.record,
        }
    }
}

fn parse_secret_name(prefix: &str, name: &str) -> Option<SecretUri> {
    let mut segments = name.split('/');
    let prefix_segment = segments.next()?;
    if prefix_segment != prefix {
        return None;
    }
    let env = segments.next()?;
    let tenant = segments.next()?;
    let team_segment = segments.next()?;
    let category = segments.next()?;
    let name_segment = segments.next()?;
    if segments.next().is_some() {
        return None;
    }

    let team = if team_segment == TEAM_PLACEHOLDER {
        None
    } else {
        Some(team_segment.to_string())
    };

    let scope = Scope::new(env.to_string(), tenant.to_string(), team).ok()?;
    SecretUri::new(scope, category, name_segment).ok()
}

fn deserialize_secret_payload(
    secret_string: Option<&str>,
    secret_binary: Option<&aws_smithy_types::Blob>,
) -> SecretsResult<Option<StoredSecret>> {
    if let Some(value) = secret_string {
        if value.trim().is_empty() {
            return Ok(None);
        }
        return serde_json::from_str::<StoredSecret>(value)
            .map(Some)
            .map_err(|err| SecretsError::Storage(format!("decode secret payload: {err}")));
    }

    if let Some(blob) = secret_binary {
        let bytes = blob.as_ref();
        if bytes.is_empty() {
            return Ok(None);
        }
        return serde_json::from_slice::<StoredSecret>(bytes)
            .map(Some)
            .map_err(|err| SecretsError::Storage(format!("decode secret payload: {err}")));
    }

    Ok(None)
}

fn is_not_found<T>(err: &SdkError<T>) -> bool
where
    T: aws_smithy_types::error::metadata::ProvideErrorMetadata + Send + Sync + std::fmt::Debug,
{
    if let SdkError::ServiceError(context) = err {
        return context.err().code() == Some("ResourceNotFoundException");
    }
    false
}

fn storage_error<T>(operation: &str, err: SdkError<T>) -> SecretsError
where
    T: std::fmt::Display,
{
    SecretsError::Storage(format!("{operation} failed: {err}"))
}
