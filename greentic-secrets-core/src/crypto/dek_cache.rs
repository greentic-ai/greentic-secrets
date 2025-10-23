use crate::types::{Scope, SecretMeta};
use lru::LruCache;
use std::env;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const DEFAULT_CACHE_CAPACITY: usize = 256;
const DEFAULT_TTL_SECS: u64 = 300;
const TTL_ENV: &str = "SECRETS_DEK_CACHE_TTL_SECS";

/// Material returned from the cache containing both plaintext and wrapped DEKs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DekMaterial {
    pub dek: Vec<u8>,
    pub wrapped: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
}

impl CacheKey {
    pub fn new(scope: &Scope, category: &str) -> Self {
        Self {
            env: scope.env().to_string(),
            tenant: scope.tenant().to_string(),
            team: scope.team().map(ToString::to_string),
            category: category.to_string(),
        }
    }

    pub fn from_meta(meta: &SecretMeta) -> Self {
        Self::new(meta.scope(), meta.uri.category())
    }
}

#[derive(Clone, Debug)]
struct CacheValue {
    dek: Vec<u8>,
    wrapped: Vec<u8>,
    expires_at: Instant,
}

/// In-memory LRU cache for data-encryption keys.
pub struct DekCache {
    ttl: Duration,
    inner: LruCache<CacheKey, CacheValue>,
}

impl DekCache {
    /// Construct a cache with the provided capacity and TTL.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let size = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            ttl,
            inner: LruCache::new(size),
        }
    }

    /// Construct a cache using environment-driven defaults.
    pub fn from_env() -> Self {
        let ttl = env::var(TTL_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TTL_SECS));
        Self::new(DEFAULT_CACHE_CAPACITY, ttl)
    }

    /// Cache TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Fetch a DEK from the cache if present and not expired.
    pub fn get(&mut self, key: &CacheKey) -> Option<DekMaterial> {
        self.get_with_now(key, Instant::now())
    }

    /// Insert or update a cached DEK.
    pub fn insert(&mut self, key: CacheKey, dek: Vec<u8>, wrapped: Vec<u8>) {
        self.insert_with_now(key, dek, wrapped, Instant::now());
    }

    #[cfg(test)]
    pub(crate) fn get_at(&mut self, key: &CacheKey, now: Instant) -> Option<DekMaterial> {
        self.get_with_now(key, now)
    }

    #[cfg(test)]
    pub(crate) fn insert_at(
        &mut self,
        key: CacheKey,
        dek: Vec<u8>,
        wrapped: Vec<u8>,
        now: Instant,
    ) {
        self.insert_with_now(key, dek, wrapped, now);
    }

    fn insert_with_now(&mut self, key: CacheKey, dek: Vec<u8>, wrapped: Vec<u8>, now: Instant) {
        let entry = CacheValue {
            dek,
            wrapped,
            expires_at: now + self.ttl,
        };
        self.inner.put(key, entry);
    }

    fn get_with_now(&mut self, key: &CacheKey, now: Instant) -> Option<DekMaterial> {
        self.purge_expired(now);
        self.inner.get(key).map(|value| DekMaterial {
            dek: value.dek.clone(),
            wrapped: value.wrapped.clone(),
        })
    }

    fn purge_expired(&mut self, now: Instant) {
        let expired: Vec<CacheKey> = self
            .inner
            .iter()
            .filter_map(|(key, value)| {
                if value.expires_at <= now {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            self.inner.pop(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentType, SecretMeta, Visibility};
    use crate::uri::SecretUri;

    fn sample_meta(team: Option<&str>) -> SecretMeta {
        let scope = Scope::new(
            "prod".to_string(),
            "acme".to_string(),
            team.map(|t| t.to_string()),
        )
        .unwrap();
        let uri = SecretUri::new(scope.clone(), "kv", "api")
            .unwrap()
            .with_version(Some("v1"))
            .unwrap();
        SecretMeta::new(uri, Visibility::Team, ContentType::Opaque)
    }

    #[test]
    fn cache_hit_and_miss() {
        let mut cache = DekCache::new(4, Duration::from_secs(5));
        let meta = sample_meta(Some("payments"));
        let key = CacheKey::from_meta(&meta);

        assert!(cache.get(&key).is_none());
        cache.insert(key.clone(), vec![1; 32], vec![2; 48]);
        let material = cache.get(&key).expect("cache hit");
        assert_eq!(material.dek, vec![1; 32]);
        assert_eq!(material.wrapped, vec![2; 48]);
    }

    #[test]
    fn cache_expiry() {
        let mut cache = DekCache::new(4, Duration::from_millis(1));
        let meta = sample_meta(Some("payments"));
        let key = CacheKey::from_meta(&meta);
        let now = Instant::now();
        cache.insert_at(key.clone(), vec![3; 32], vec![4; 48], now);
        assert!(cache.get_at(&key, now).is_some());
        assert!(cache.get_at(&key, now + Duration::from_millis(2)).is_none());
    }
}
