//! Fleet-wide sub-resource cache in Redis (rb-only feature `redis-cache`).
//!
//! The process-wide `ResourceCache` already stops a pod's worker processes
//! from re-downloading the same CDN asset. This layer extends it across the
//! whole fleet: every pod that scrapes the same site shares one Redis-backed
//! copy of its static assets, so a site's jQuery, theme CSS, and fonts are
//! downloaded once per fleet per TTL instead of once per pod per process.
//!
//! Sharing rules are deliberately stricter than the per-process cache:
//! only `cache-control: public` responses with a usable max-age are stored,
//! and requests carrying credentials with cookies were already excluded
//! upstream of this layer. A pod never shares session state through this
//! cache — cookies, localStorage, and the storage dir are untouched.
//!
//! Redis is an optional acceleration, never a dependency: any error
//! (missing server, slow read, corrupt entry) falls back to the wire.

use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

/// Responses with a smaller max-age are not worth a shared round-trip; the
/// coordination cost outweighs a refetch.
const SHARED_MIN_MAX_AGE_SECS: u64 = 60;
/// Redis TTL cap. Shared entries never outlive the fleet's scrape cadence
/// even when a site sends a years-long max-age.
const SHARED_MAX_TTL_SECS: u64 = 7 * 24 * 3600;
/// Bodies larger than this are not shared (Redis holds small, hot assets;
/// big media belongs on a CDN, not in everyone's shared cache).
const SHARED_DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound for a shared-cache read. Redis is on the LAN, so a slow or
/// wedged server degrades to a fetch instead of stalling every miss.
const SHARED_LOOKUP_TIMEOUT: Duration = Duration::from_millis(150);

const KEY_PREFIX: &str = "obscura:asset:v1:";

/// One shared entry. `body` is base64 inside JSON: Redis stores bytes fine,
/// but the surrounding envelope stays inspectable with any client.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SharedEntry {
    pub(crate) status: u16,
    /// Lowercased response headers, as the local cache stores them.
    pub(crate) headers: Vec<(String, String)>,
    #[serde(with = "base64_bytes")]
    pub(crate) body: Vec<u8>,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
    /// The response's `max-age` in seconds, kept so a reader can honor the
    /// origin's freshness even if the Redis TTL was capped.
    pub(crate) max_age: u64,
    /// Wall-clock seconds when the entry was fetched; guards against Redis
    /// TTL drift and clock skew across pods.
    pub(crate) fetched_at: u64,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// A response is shareable across the fleet only when the origin said so
/// explicitly: `public` (not merely unmarked, and never `private`) with a
/// max-age long enough to amortize the round-trips. The per-process cache
/// is more permissive because it never crosses pod boundaries.
pub(crate) fn shared_cache_max_age(response: &crate::Response) -> Option<u64> {
    if response.status != 200 || !response.redirected_from.is_empty() {
        return None;
    }
    if response.header("set-cookie").is_some() {
        return None;
    }
    if response
        .header("vary")
        .is_some_and(|vary| vary.split(',').any(|name| name.trim() == "*"))
    {
        return None;
    }
    let cache_control = response.header("cache-control")?;
    let mut public = false;
    let mut max_age = None;
    for directive in cache_control.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "public" {
            public = true;
        }
        if lower == "private" || lower == "no-store" || lower == "no-cache" {
            return None;
        }
        if let Some(value) = lower.strip_prefix("max-age=") {
            max_age = value.trim_matches('"').parse::<u64>().ok();
        }
    }
    if !public {
        return None;
    }
    max_age.filter(|seconds| *seconds >= SHARED_MIN_MAX_AGE_SECS)
}

pub(crate) struct SharedAssetCache {
    manager: ConnectionManager,
    /// Bodies larger than this are not stored.
    max_body_bytes: usize,
}

static SHARED_ASSET_CACHE: tokio::sync::OnceCell<Option<SharedAssetCache>> =
    tokio::sync::OnceCell::const_new();

/// The process-wide shared cache, initialized from the environment on first
/// use. `OBSCURA_SHARED_ASSET_CACHE_URL` (e.g. `redis://host:6379/0`, with
/// credentials as `redis://:password@host:6379/0`) enables it; without the
/// variable every call is a cheap `None`. A URL that cannot be connected at
/// first use disables the layer for the process with one warning: a scraping
/// run must never depend on Redis being up.
pub(crate) async fn shared_asset_cache() -> Option<&'static SharedAssetCache> {
    SHARED_ASSET_CACHE
        .get_or_init(|| async {
            let url = std::env::var("OBSCURA_SHARED_ASSET_CACHE_URL").ok()?;
            let max_body_bytes = std::env::var("OBSCURA_SHARED_ASSET_CACHE_MAX_BYTES")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|bytes| *bytes > 0)
                .unwrap_or(SHARED_DEFAULT_MAX_BODY_BYTES);
            let connected = async {
                let client = redis::Client::open(url.as_str()).ok()?;
                let manager = client.get_connection_manager().await.ok()?;
                Some(SharedAssetCache {
                    manager,
                    max_body_bytes,
                })
            };
            match tokio::time::timeout(SHARED_LOOKUP_TIMEOUT, connected).await {
                Ok(Some(cache)) => {
                    tracing::info!("Shared asset cache enabled: {url}");
                    Some(cache)
                }
                Ok(None) | Err(_) => {
                    tracing::warn!("Shared asset cache unreachable, sharing disabled: {url}");
                    None
                }
            }
        })
        .await
        .as_ref()
}

/// Deterministic digest of the fields that make two requests identical.
/// DefaultHasher is seeded with fixed keys, so every pod running this build
/// derives the same key for the same request — no shared key registry
/// needed, and signed URLs never leak into Redis keys.
pub(crate) fn shared_cache_key(
    url: &str,
    user_agent: &str,
    resource_type: &str,
    credentials: &str,
) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    user_agent.hash(&mut hasher);
    resource_type.hash(&mut hasher);
    credentials.hash(&mut hasher);
    let digest = hasher.finish();
    format!("{KEY_PREFIX}{digest:016x}")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

impl SharedAssetCache {
    /// Look up one asset. `Err` never escapes: any failure is a miss.
    pub(crate) async fn lookup(&self, key: &str) -> Option<SharedEntry> {
        let raw: Option<Vec<u8>> = match tokio::time::timeout(
            SHARED_LOOKUP_TIMEOUT,
            self.manager.clone().get(key),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                tracing::debug!("Shared asset cache read failed: {error}");
                return None;
            }
            Err(_) => {
                tracing::debug!("Shared asset cache read timed out");
                return None;
            }
        };
        let raw = raw?;
        match serde_json::from_slice::<SharedEntry>(&raw) {
            Ok(entry) => Some(entry),
            Err(error) => {
                // Another version wrote the key; treat as a miss and let the
                // write-back overwrite it.
                tracing::debug!("Shared asset cache entry undecodable: {error}");
                None
            }
        }
    }

    /// Fire-and-forget store. The caller never waits on Redis; a failed write
    /// only costs the next reader one wire fetch.
    pub(crate) fn store(&self, key: String, entry: SharedEntry) {
        let Ok(body) = serde_json::to_vec(&entry) else {
            return;
        };
        let ttl = entry.max_age.min(SHARED_MAX_TTL_SECS);
        let mut manager = self.manager.clone();
        tokio::spawn(async move {
            let result: Result<(), redis::RedisError> = manager.set_ex(key, body, ttl).await;
            if let Err(error) = result {
                tracing::debug!("Shared asset cache write failed: {error}");
            }
        });
    }

    pub(crate) fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

/// Build a shared entry from a response when the origin allows sharing.
pub(crate) fn shared_entry_for(response: &crate::Response) -> Option<SharedEntry> {
    let max_age = shared_cache_max_age(response)?;
    Some(SharedEntry {
        status: response.status,
        headers: response
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body: response.body.clone(),
        etag: response.header("etag").map(str::to_string),
        last_modified: response.header("last-modified").map(str::to_string),
        max_age,
        fetched_at: now_secs(),
    })
}

/// Freshness left on a shared entry, honoring the origin's max-age and the
/// Redis TTL cap, whichever expires first. `None` means the entry is stale:
/// a reader refetches rather than serve a body the origin may have replaced.
pub(crate) fn shared_entry_remaining(entry: &SharedEntry) -> Option<Duration> {
    let age = now_secs().saturating_sub(entry.fetched_at);
    let capped = entry.max_age.min(SHARED_MAX_TTL_SECS);
    capped.checked_sub(age).map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn response(headers: &[(&str, &str)], body: &str) -> crate::Response {
        crate::Response {
            url: url::Url::parse("https://cdn.test/lib.js").unwrap(),
            status: 200,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect::<HashMap<String, String>>(),
            body: body.as_bytes().to_vec(),
            redirected_from: Vec::new(),
        }
    }

    #[test]
    fn only_public_max_age_responses_are_shareable() {
        let shared = response(&[("cache-control", "public, max-age=3600")], "ok");
        assert_eq!(shared_cache_max_age(&shared), Some(3600));

        let private = response(&[("cache-control", "private, max-age=3600")], "ok");
        assert_eq!(shared_cache_max_age(&private), None);

        let unmarked = response(&[("cache-control", "max-age=3600")], "ok");
        assert_eq!(
            shared_cache_max_age(&unmarked),
            None,
            "an unmarked response stays per-process; only the origin's explicit public crosses pods"
        );

        let short = response(&[("cache-control", "public, max-age=30")], "ok");
        assert_eq!(shared_cache_max_age(&short), None);

        let no_store = response(&[("cache-control", "public, max-age=3600, no-store")], "ok");
        assert_eq!(shared_cache_max_age(&no_store), None);

        let set_cookie = response(
            &[
                ("cache-control", "public, max-age=3600"),
                ("set-cookie", "session=1"),
            ],
            "ok",
        );
        assert_eq!(shared_cache_max_age(&set_cookie), None);

        let vary_star = response(
            &[
                ("cache-control", "public, max-age=3600"),
                ("vary", "Accept, *"),
            ],
            "ok",
        );
        assert_eq!(shared_cache_max_age(&vary_star), None);
    }

    #[test]
    fn shared_entries_round_trip_through_json() {
        let entry = shared_entry_for(&response(
            &[("cache-control", "public, max-age=7200"), ("etag", "\"v9\"")],
            "asset body",
        ))
        .unwrap();
        assert_eq!(entry.max_age, 7200);
        assert_eq!(entry.etag.as_deref(), Some("\"v9\""));

        let encoded = serde_json::to_vec(&entry).unwrap();
        let decoded: SharedEntry = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.body, b"asset body".to_vec());
        assert!(decoded
            .headers
            .iter()
            .any(|(name, value)| name == "etag" && value == "\"v9\""));
        assert_eq!(
            shared_entry_remaining(&decoded).map(|remaining| remaining.as_secs()),
            Some(7200)
        );

        let aged = SharedEntry {
            fetched_at: entry.fetched_at.saturating_sub(7201),
            ..decoded.clone()
        };
        assert!(shared_entry_remaining(&aged).is_none());

        // The TTL cap wins over a years-long max-age.
        let long = SharedEntry {
            max_age: 100 * 365 * 24 * 3600,
            ..decoded
        };
        assert_eq!(
            shared_entry_remaining(&long).map(|remaining| remaining.as_secs()),
            Some(SHARED_MAX_TTL_SECS)
        );
    }

    #[test]
    fn keys_are_deterministic_and_request_shaped() {
        let a = shared_cache_key("https://cdn.test/lib.js", "UA", "Script", "Omit");
        let b = shared_cache_key("https://cdn.test/lib.js", "UA", "Script", "Omit");
        let other_ua = shared_cache_key("https://cdn.test/lib.js", "UA2", "Script", "Omit");
        assert_eq!(a, b);
        assert_ne!(a, other_ua);
        assert!(a.starts_with("obscura:asset:v1:"));
    }
}

#[cfg(test)]
mod redis_tests {
    use super::*;
    use crate::client::{ObscuraHttpClient, ResourceRequest, ResourceType};
    use crate::cookies::CookieJar;
    use std::sync::Arc;
    use std::time::Duration;
    use url::Url;

    // Wire-level test against a real Redis (nextest gives every test its own
    // process, so the process-wide statics are private to this test).
    // Skipped unless OBSCURA_REDIS_TEST_URL points at a disposable instance:
    // `docker run --rm -p 6390:6379 redis:8-alpine`
    #[tokio::test]
    async fn shared_cache_serves_an_asset_across_local_cache_flushes() {
        let Some(url) = std::env::var("OBSCURA_REDIS_TEST_URL").ok() else {
            eprintln!("skipping: OBSCURA_REDIS_TEST_URL not set");
            return;
        };
        std::env::set_var("OBSCURA_SHARED_ASSET_CACHE_URL", &url);
        // The instance is disposable per the skip note; flush it so leftover
        // keys from earlier runs cannot break the hygiene assert below.
        {
            let client = redis::Client::open(url.as_str()).unwrap();
            let mut conn = client.get_connection_manager().await.unwrap();
            redis::cmd("FLUSHDB")
                .query_async::<()>(&mut conn)
                .await
                .unwrap();
        }

        let body = "let shared = 'fleet';";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nETag: \"v1\"\r\nCache-Control: public, max-age=3600\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = requests.clone();
        let wire_response = Arc::new(response);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let observed = observed.clone();
                let wire_response = wire_response.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut scratch = [0u8; 2048];
                    let _ = stream.read(&mut scratch).await;
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = stream.write_all(wire_response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let target = Url::parse(&format!("http://{address}/lib.js")).unwrap();
        let initiator = target.join("/page.html").unwrap();
        let client = ObscuraHttpClient::with_full_options(Arc::new(CookieJar::new()), None, true);
        let request = ResourceRequest::subresource(ResourceType::Script, &initiator);

        let first = client
            .fetch_resource_with_callbacks(&target, request.clone(), None)
            .await
            .unwrap();
        assert_eq!(first.status, 200);
        assert_eq!(first.body, body.as_bytes());

        // The fire-and-forget write-back must land before the next read.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if requests.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                // give the spawned write one more poll cycle
                tokio::time::sleep(Duration::from_millis(50)).await;
                break;
            }
        }

        // Simulate another pod in this process: wipe the local cache; the
        // fetch must come from Redis, not the wire.
        crate::client::clear_process_resource_cache_for_tests();
        let second = client
            .fetch_resource_with_callbacks(&target, request, None)
            .await
            .unwrap();
        assert_eq!(second.status, 200);
        assert_eq!(second.body, body.as_bytes());
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second fetch must be served by the shared cache"
        );

        // Hygiene: the key exists and the TTL matches max-age.
        let client = redis::Client::open(url.as_str()).unwrap();
        let mut conn = client.get_connection_manager().await.unwrap();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("obscura:asset:v1:*")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        let ttl: i64 = redis::cmd("TTL").arg(&keys[0]).query_async(&mut conn).await.unwrap();
        assert!(ttl > 3000, "TTL should track max-age, got {ttl}");
    }
}
