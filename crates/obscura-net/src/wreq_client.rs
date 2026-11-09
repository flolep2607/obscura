#[cfg(feature = "stealth")]
use std::collections::HashMap;
#[cfg(feature = "stealth")]
use std::error::Error;
#[cfg(feature = "stealth")]
use std::sync::Arc;
#[cfg(feature = "stealth")]
use std::time::Duration;

#[cfg(feature = "stealth")]
use futures_util::StreamExt;
#[cfg(feature = "stealth")]
use tokio::sync::RwLock;
#[cfg(feature = "stealth")]
use url::Url;

#[cfg(feature = "stealth")]
use crate::client::{
    cors_required, env_allows_private_network, error_chain, fetch_file_url, is_forbidden_ip,
    redirect_taints_origin, request_fetch_site, request_origin_header, request_referrer, response_too_large,
    same_site_context, serialized_request_origin, validate_cors_response, validate_request_mode,
    validate_url, CallbackRegistry, InFlightGuard, ObscuraNetError, RequestInfo, RequestMode,
    ResourceRequest, Response, SsrfGuardResolver,
};
#[cfg(feature = "stealth")]
use crate::cookies::{CookieJar, SameSiteContext};

/// The wreq half of [`SsrfGuardResolver`]. `validate_url` only inspects the
/// host *string*, so on its own it lets a public name that resolves inward
/// straight through — the reqwest client closes that with a `dns_resolver`, and
/// until this impl existed the stealth client did not, which made `--stealth` a
/// downgrade in protection rather than only a change of fingerprint. The
/// deny-set is shared, so the two transports cannot drift apart.
#[cfg(feature = "stealth")]
impl wreq::dns::Resolve for SsrfGuardResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let allow = self.allow_private || env_allows_private_network();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?
                .collect();
            if !allow {
                if let Some(bad) = addrs.iter().find(|sa| is_forbidden_ip(sa.ip())) {
                    return Err(format!(
                        "SSRF blocked: '{}' resolves to forbidden address {}",
                        host,
                        bad.ip()
                    )
                    .into());
                }
            }
            let iter: wreq::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(feature = "stealth")]
pub const STEALTH_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

// The wreq emulation (Profile::Chrome145, Platform::Windows) sends this exact
// UA and sec-ch-ua-platform "Windows" on the wire. navigator has to report the
// same identity, otherwise the TLS/HTTP layer and the JS layer disagree and a
// site cross-checks the mismatch as a bot signal.
#[cfg(feature = "stealth")]
pub const STEALTH_NAVIGATOR_PLATFORM: &str = "Win32";
#[cfg(feature = "stealth")]
pub const STEALTH_UA_PLATFORM: &str = "Windows";
#[cfg(feature = "stealth")]
pub const STEALTH_UA_PLATFORM_VERSION: &str = "15.0.0";

#[cfg(feature = "stealth")]
fn tracker_blocking_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim),
        Some(value) if matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
    )
}

#[cfg(feature = "stealth")]
fn is_tracker_blocked(url: &Url, block_trackers: bool) -> bool {
    block_trackers && url.host_str().is_some_and(crate::blocklist::is_blocked)
}

#[cfg(feature = "stealth")]
fn wreq_response_header_value<'a>(
    headers: &'a wreq::header::HeaderMap,
    name: &'static str,
    url: &Url,
) -> Result<Option<&'a str>, ObscuraNetError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ObscuraNetError::Cors(format!(
            "{} returned multiple {} headers",
            url, name
        )));
    }
    first.to_str().map(Some).map_err(|_| {
        ObscuraNetError::Cors(format!("{} returned an invalid {} header", url, name))
    })
}

#[cfg(feature = "stealth")]
fn validate_wreq_cors_response(
    request: &ResourceRequest,
    target: &Url,
    serialized_origin: &str,
    headers: &wreq::header::HeaderMap,
) -> Result<(), ObscuraNetError> {
    if !cors_required(request, target) {
        return Ok(());
    }
    let allow_origin =
        wreq_response_header_value(headers, "access-control-allow-origin", target)?;
    let allow_credentials =
        wreq_response_header_value(headers, "access-control-allow-credentials", target)?;
    validate_cors_response(
        request,
        target,
        serialized_origin,
        allow_origin,
        allow_credentials,
    )
}

#[cfg(feature = "stealth")]
async fn read_wreq_body_limited(
    response: wreq::Response,
    url: &Url,
    limit: usize,
) -> Result<Vec<u8>, ObscuraNetError> {
    if response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|length| length > limit as u64)
    {
        return Err(response_too_large(url, limit));
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(limit);
    let stream = response.bytes_stream();
    futures_util::pin_mut!(stream);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            ObscuraNetError::Network(format!("Failed to read body: {}", error_chain(&error)))
        })?;
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(response_too_large(url, limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "stealth")]
async fn send_get_with_connection_reset_retry(
    request: wreq::RequestBuilder,
    url: &Url,
) -> Result<wreq::Response, wreq::Error> {
    let retry = request.try_clone();
    match request.send().await {
        Err(error) if error.is_connection_reset() => {
            let Some(retry) = retry else {
                return Err(error);
            };
            tracing::debug!(%url, "retrying GET after connection reset");
            retry.send().await
        }
        result => result,
    }
}

/// wreq surfaces only BoringSSL's reason code, CERTIFICATE_VERIFY_FAILED, not
/// the X509 verify result that distinguishes a missing issuer from an expired
/// or mismatched certificate. So this only selects candidates; the chain read
/// by `probe_chain` decides whether an intermediate is actually missing.
#[cfg(feature = "stealth")]
fn is_verify_failure(error: &wreq::Error) -> bool {
    let mut source: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(e) = source {
        if format!("{e:?}").contains("CERTIFICATE_VERIFY_FAILED") {
            return true;
        }
        source = e.source();
    }
    false
}

/// True when the topmost certificate of `chain` was issued by a root in the
/// bundled webpki set, so nothing is missing and fetching would not help.
/// Only meaningful when the default roots are in use.
#[cfg(feature = "stealth")]
fn chain_reaches_bundled_root(chain: &[Vec<u8>]) -> bool {
    static SUBJECTS: std::sync::OnceLock<std::collections::HashSet<Vec<u8>>> =
        std::sync::OnceLock::new();
    let subjects = SUBJECTS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|root| crate::aia::subject_name(root))
            .collect()
    });
    crate::aia::tip_issuer_name(chain).is_some_and(|issuer| subjects.contains(&issuer))
}

/// What makes two stealth clients interchangeable: proxy, SSRF gate and the custom-CA environment `build_client` reads.
#[cfg(feature = "stealth")]
type ClientKey = (Option<String>, bool, Option<std::ffi::OsString>, Option<std::ffi::OsString>);

#[cfg(feature = "stealth")]
static SHARED_CLIENTS: std::sync::OnceLock<std::sync::Mutex<HashMap<ClientKey, (wreq::Client, u64)>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "stealth")]
fn client_key(proxy_url: Option<&str>, allow_private_network: bool) -> ClientKey {
    (
        proxy_url.map(str::to_string),
        allow_private_network,
        std::env::var_os("SSL_CERT_FILE"),
        std::env::var_os("SSL_CERT_DIR"),
    )
}

/// Single-flight dialing per origin. The pool cannot know before the handshake whether an origin speaks HTTP/2, so N
/// parallel requests to an origin with no live connection each dial their own TCP+TLS connection and all but one are
/// dropped after the handshake (measured: 1 in 5 connections of a page load, 30 at once for one product page). The
/// first request to such an origin goes alone (the scout); the others wait for its response headers and then find the
/// pooled HTTP/2 connection, or dial in parallel when the origin turned out to be HTTP/1.1. An origin counts as having
/// a live connection only while a request that already got its headers is still running: servers close HTTP/2
/// connections as soon as a response ends (measured: a document's connection closed 0.3 s before the page's script
/// burst), so any timer-based "warm" window let that burst dial 30 connections in parallel. A scout that fails or
/// hangs holds nobody up for longer than `SCOUT_WAIT`.
#[cfg(feature = "stealth")]
pub(crate) struct DialGate {
    scout: Arc<tokio::sync::Mutex<()>>,
    /// Requests that got their response headers and have not finished yet.
    proven: std::sync::atomic::AtomicU32,
}

/// One request's standing at its origin's gate; hold it until the response body is read.
#[cfg(feature = "stealth")]
pub(crate) struct DialTicket {
    gate: Arc<DialGate>,
    scout: Option<tokio::sync::OwnedMutexGuard<()>>,
    proven: bool,
}

#[cfg(feature = "stealth")]
const SCOUT_WAIT: Duration = Duration::from_secs(2);

#[cfg(feature = "stealth")]
fn dial_gate(proxy_url: Option<&str>, url: &Url) -> Arc<DialGate> {
    static GATES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<DialGate>>>> = std::sync::OnceLock::new();
    let origin = format!("{}|{}://{}:{}", proxy_url.unwrap_or(""), url.scheme(), url.host_str().unwrap_or(""), url.port_or_known_default().unwrap_or(0));
    GATES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(origin)
        .or_insert_with(|| {
            Arc::new(DialGate { scout: Arc::default(), proven: 0.into() })
        })
        .clone()
}

#[cfg(feature = "stealth")]
impl DialGate {
    pub(crate) async fn enter(self: &Arc<Self>) -> DialTicket {
        use std::sync::atomic::Ordering::Relaxed;
        let mut ticket = DialTicket { gate: self.clone(), scout: None, proven: false };
        if self.proven.load(Relaxed) > 0 || std::env::var_os("OBSCURA_NO_DIAL_GATE").is_some() {
            return ticket;
        }
        match self.scout.clone().try_lock_owned() {
            Ok(guard) => ticket.scout = Some(guard),
            Err(_) => {
                let _ = tokio::time::timeout(SCOUT_WAIT, self.scout.lock()).await;
            }
        }
        ticket
    }
}

#[cfg(feature = "stealth")]
impl DialTicket {
    /// The response headers arrived, so the origin has a connection: let the waiting requests go.
    pub(crate) fn settle(&mut self) {
        if !self.proven {
            self.proven = true;
            self.gate.proven.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.scout = None;
    }
}

#[cfg(feature = "stealth")]
impl Drop for DialTicket {
    fn drop(&mut self) {
        if self.proven {
            self.gate.proven.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "stealth")]
pub struct StealthHttpClient {
    /// The client and the AIA cache generation it was built at.
    client: std::sync::RwLock<(wreq::Client, u64)>,
    proxy_url: Option<String>,
    allow_private_network: bool,
    /// Lets `fetch_file_url` read local files. Off by default.
    pub allow_file_access: bool,
    pub block_trackers: bool,
    pub cookie_jar: Arc<CookieJar>,
    pub extra_headers: RwLock<HashMap<String, String>>,
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
    user_agent: Option<String>,
}

/// Scripted fetch exposes these headers before consuming the bounded body.
#[cfg(feature = "stealth")]
pub struct StealthResponseHeaders {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: futures_util::future::BoxFuture<'static, Result<Vec<u8>, ObscuraNetError>>,
}

#[cfg(feature = "stealth")]
impl StealthHttpClient {
    pub fn new(cookie_jar: Arc<CookieJar>) -> Self {
        Self::with_proxy(cookie_jar, None, false)
    }

    pub fn with_proxy(
        cookie_jar: Arc<CookieJar>,
        proxy_url: Option<&str>,
        allow_private_network: bool,
    ) -> Self {
        let (client, generation) = Self::shared_client(proxy_url, allow_private_network);

        StealthHttpClient {
            client: std::sync::RwLock::new((client, generation)),
            proxy_url: proxy_url.map(str::to_string),
            allow_private_network,
            allow_file_access: false,
            block_trackers: tracker_blocking_enabled(
                std::env::var("OBSCURA_BLOCK_TRACKERS").ok().as_deref(),
            ),
            cookie_jar,
            extra_headers: RwLock::new(HashMap::new()),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            user_agent: None,
        }
    }

    /// The process-wide client for these transport settings, built on first use. Every page, iframe and CDP
    /// connection in the process shares its connection pool and TLS session cache, so one origin costs one
    /// HTTP/2 connection per process instead of one per page. wreq keeps no cookies (the jar lives in
    /// `StealthHttpClient`) and no per-request state, so sharing it leaks nothing between contexts.
    fn shared_client(proxy_url: Option<&str>, allow_private_network: bool) -> (wreq::Client, u64) {
        let mut clients = SHARED_CLIENTS.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
        clients
            .entry(client_key(proxy_url, allow_private_network))
            .or_insert_with(|| {
                let generation = crate::aia::generation();
                let client = Self::build_client(proxy_url, allow_private_network, &crate::aia::cached_certificates(), false);
                (client, generation)
            })
            .clone()
    }

    /// Build the Chrome-emulating client. `intermediates` are AIA-fetched
    /// certificates (see aia.rs); `probe` builds the verification-off variant
    /// that only reads a failing server's chain.
    fn build_client(
        proxy_url: Option<&str>,
        allow_private_network: bool,
        intermediates: &[Arc<[u8]>],
        probe: bool,
    ) -> wreq::Client {
        let emulation_opts = wreq_util::Emulation::builder()
            .profile(wreq_util::Profile::Chrome145)
            .platform(wreq_util::Platform::Windows)
            .build();

        let mut builder = wreq::Client::builder()
            .emulation(emulation_opts)
            // Read a folded header line (obs-fold) as Chrome does instead of
            // failing the response. Set after `emulation()`, which overwrites
            // `http1_options`; the Chrome profile leaves them unset.
            .http1_options(
                wreq::http1::Http1Options::builder()
                    .allow_obsolete_multiline_headers_in_responses(true)
                    .build(),
            )
            .timeout(Duration::from_secs(30))
            // SSRF guard: reject hostnames that resolve to a private/loopback
            // IP. Use the same opt-in as the `validate_url` calls below so
            // `--allow-private-network` reaches this transport (#793); the
            // resolver still honours OBSCURA_ALLOW_PRIVATE_NETWORK on its own.
            .dns_resolver(Arc::new(SsrfGuardResolver::new(allow_private_network)))
            .redirect(wreq::redirect::Policy::none());

        // Honor SSL_CERT_FILE / SSL_CERT_DIR in the stealth client too.
        //
        // `client.rs` (the reqwest path) already reads these via `configured_root_paths()` and
        // feeds `add_root_certificate`, so a private CA works there. This client did not, which
        // made the *better-fingerprinted* transport the only one unable to reach hosts behind a
        // private/national CA (measured against a Brazilian government portal whose leaf is
        // issued by an ICP-Brasil intermediate: `--stealth` failed with CERTIFICATE_VERIFY_FAILED
        // while the reqwest path, with SSL_CERT_FILE set, completed the handshake).
        //
        // Two deliberate constraints:
        //
        // 1. `tls_cert_store` is used, NOT `tls_options`. `emulation()` overwrites `tls_options`
        //    wholesale ("This will overwrite the existing configuration"), so setting TLS options
        //    here would silently discard the Chrome fingerprint — the whole point of this client.
        //    `tls_cert_store` is a separate field on the config and composes with emulation.
        //
        // 2. Opt-in only. Supplying a store REPLACES the webpki roots (see `set_cert_store` in
        //    `tls/conn/ext.rs`), it does not add to them. Applying it unconditionally would break
        //    every ordinary site whenever the bundle is incomplete. With neither variable set,
        //    behaviour is byte-for-byte what it was before.
        if crate::client::custom_cert_store_requested(
            std::env::var_os("SSL_CERT_FILE").as_deref(),
            std::env::var_os("SSL_CERT_DIR").as_deref(),
        ) {
            let mut store = wreq::tls::trust::CertStore::builder().set_default_paths();
            for der in intermediates {
                store = store.add_der_cert(&der[..]);
            }
            match store.build() {
                Ok(store) => builder = builder.tls_cert_store(store),
                Err(error) => tracing::warn!(
                    %error,
                    "SSL_CERT_FILE/SSL_CERT_DIR set but the certificate store failed to build; \
                     continuing with the default roots"
                ),
            }
        } else if !intermediates.is_empty() {
            // AIA-fetched intermediates (see aia.rs). A store REPLACES the
            // bundled roots, so rebuild the same webpki set and add them. They
            // are plain store entries, not trust anchors: BoringSSL still needs
            // a chain to a self-signed root (no PARTIAL_CHAIN flag is set).
            let mut store = wreq::tls::trust::CertStore::builder().add_der_certs(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().map(|c| c.as_ref()),
            );
            for der in intermediates {
                store = store.add_der_cert(&der[..]);
            }
            match store.build() {
                Ok(store) => builder = builder.tls_cert_store(store),
                Err(error) => tracing::warn!(%error, "AIA intermediates not applied"),
            }
        }
        if probe {
            // Only to read the chain of a server that failed verification
            // (see `probe_chain`).
            builder = builder.tls_cert_verification(false).tls_info(true);
        }

        if let Some(proxy) = proxy_url {
            if let Ok(p) = wreq::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        builder.build().expect("failed to build wreq stealth client")
    }

    fn current_client(&self) -> wreq::Client {
        self.client.read().unwrap_or_else(|p| p.into_inner()).0.clone()
    }

    /// Rebuild the client with every cached AIA intermediate in its store.
    fn rebuild_with_cached_intermediates(&self) {
        let generation = crate::aia::generation();
        let client = Self::build_client(
            self.proxy_url.as_deref(),
            self.allow_private_network,
            &crate::aia::cached_certificates(),
            false,
        );
        // Publish it so pages created later start with the intermediates too.
        SHARED_CLIENTS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(client_key(self.proxy_url.as_deref(), self.allow_private_network), (client.clone(), generation));
        *self.client.write().unwrap_or_else(|p| p.into_inner()) = (client, generation);
    }

    /// Chain presented by `url`'s server, read without verification. This
    /// completes a TLS handshake and sends `HEAD /` with no cookies or custom
    /// headers; it runs only after the verified request already failed for a
    /// missing issuer, uses the same Chrome emulation, proxy and SSRF resolver,
    /// and nothing from the response is used except the certificates.
    async fn probe_chain(&self, url: &Url) -> Option<Vec<Vec<u8>>> {
        let client = Self::build_client(
            self.proxy_url.as_deref(),
            self.allow_private_network,
            &[],
            true,
        );
        let mut origin = url.clone();
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        let resp = client
            .head(origin.as_str())
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .ok()?;
        let info = resp.extensions().get::<wreq::tls::TlsInfo>()?;
        let chain: Vec<Vec<u8>> = match info.peer_certificate_chain() {
            Some(chain) => chain.map(<[u8]>::to_vec).collect(),
            None => vec![info.peer_certificate()?.to_vec()],
        };
        Some(chain)
    }

    /// After a missing-issuer failure: make the next attempt's client able to
    /// complete the chain. True when a retry is worthwhile.
    async fn refresh_intermediates(&self, url: &Url) -> bool {
        let built_at = self.client.read().unwrap_or_else(|p| p.into_inner()).1;
        if crate::aia::generation() > built_at {
            // Another request already fetched intermediates this client lacks.
            self.rebuild_with_cached_intermediates();
            return true;
        }
        let Some(mut chain) = self.probe_chain(url).await else { return false };
        crate::aia::extend_from_cache(&mut chain);
        let custom_roots = crate::client::custom_cert_store_requested(
            std::env::var_os("SSL_CERT_FILE").as_deref(),
            std::env::var_os("SSL_CERT_DIR").as_deref(),
        );
        if (!custom_roots && chain_reaches_bundled_root(&chain))
            || !crate::aia::fetch_missing_issuer(
            &chain,
            self.allow_private_network,
            self.proxy_url.as_deref(),
        )
        .await
        {
            return false;
        }
        self.rebuild_with_cached_intermediates();
        true
    }

    /// Send `request`. If the handshake fails because the server did not send
    /// its intermediate, fetch it via AIA and retry (at most `MAX_ROUNDS`
    /// times). `reset_retry` adds the GET connection-reset retry.
    async fn send_with_aia(
        &self,
        request: wreq::RequestBuilder,
        url: &Url,
        reset_retry: bool,
    ) -> Result<(wreq::Response, DialTicket), wreq::Error> {
        let gate = dial_gate(self.proxy_url.as_deref(), url);
        let send_once = |client: wreq::Client, request: wreq::Request| {
            let gate = gate.clone();
            async move {
                let mut ticket = gate.enter().await;
                let builder = wreq::RequestBuilder::from_parts(client, request);
                let response = if reset_retry {
                    send_get_with_connection_reset_retry(builder, url).await
                } else {
                    builder.send().await
                }?;
                ticket.settle();
                Ok::<_, wreq::Error>((response, ticket))
            }
        };
        let (mut client, request) = request.build_split();
        let request = request?;
        let mut round = 0;
        loop {
            let Some(attempt) = request.try_clone() else {
                return send_once(client, request).await;
            };
            let err = match send_once(client.clone(), attempt).await {
                Ok(resp) => return Ok(resp),
                Err(err) => err,
            };
            round += 1;
            if round > crate::aia::MAX_ROUNDS
                || url.scheme() != "https"
                || !is_verify_failure(&err)
                || !self.refresh_intermediates(url).await
            {
                return Err(err);
            }
            client = self.current_client();
        }
    }

    /// Overrides the emulation's User-Agent for every request (`--user-agent`).
    /// `None` keeps the Chrome145/Windows emulation UA untouched.
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub async fn fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        self.fetch_with_callbacks(url, None).await
    }

    pub async fn fetch_with_callbacks(
        &self,
        url: &Url,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_profile(url, ResourceRequest::navigation(), callbacks)
            .await
    }

    pub async fn fetch_resource_with_callbacks(
        &self,
        url: &Url,
        request: ResourceRequest,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        // Fleet-wide asset cache (feature `redis-cache`): a hit costs no connection to the origin or its CDN.
        #[cfg(feature = "redis-cache")]
        let shared = self.shared_cache_slot(url, &request).await;
        #[cfg(feature = "redis-cache")]
        if let Some((cache, key)) = &shared {
            if let Some(entry) = cache.lookup(key).await {
                if crate::shared_cache::shared_entry_remaining(&entry).is_some() {
                    let response = Response {
                        url: url.clone(),
                        status: entry.status,
                        headers: entry.headers.into_iter().collect(),
                        body: entry.body,
                        redirected_from: Vec::new(),
                    };
                    let origin = serialized_request_origin(&request, false);
                    let cors_ok = validate_cors_response(
                        &request,
                        url,
                        &origin,
                        response.header("access-control-allow-origin"),
                        response.header("access-control-allow-credentials"),
                    )
                    .is_ok();
                    if cors_ok && response.body.len() <= request.max_response_bytes {
                        if let Some(callbacks) = callbacks {
                            let info = RequestInfo {
                                url: url.clone(),
                                method: "GET".to_string(),
                                headers: self.extra_headers.read().await.clone(),
                                resource_type: request.resource_type,
                            };
                            callbacks.fire_request(&info).await;
                            callbacks.fire_response(&info, &response).await;
                        }
                        tracing::debug!("Shared asset cache hit, connection spared: {url}");
                        return Ok(response);
                    }
                }
            }
        }
        let result = self.fetch_with_profile(url, request, callbacks).await;
        #[cfg(feature = "redis-cache")]
        if let (Some((cache, key)), Ok(response)) = (shared, &result) {
            if response.body.len() <= cache.max_body_bytes() {
                if let Some(entry) = crate::shared_cache::shared_entry_for(response) {
                    cache.store(key, entry);
                }
            }
        }
        result
    }

    /// The shared-cache key for `request`, when it may be shared: a plain static asset fetched without
    /// credentials, cookies or caller headers that could make the response personal.
    #[cfg(feature = "redis-cache")]
    async fn shared_cache_slot(
        &self,
        url: &Url,
        request: &ResourceRequest,
    ) -> Option<(&'static crate::shared_cache::SharedAssetCache, String)> {
        use crate::client::ResourceType;
        if !matches!(url.scheme(), "http" | "https")
            || !matches!(
                request.resource_type,
                ResourceType::Script | ResourceType::Stylesheet | ResourceType::Image | ResourceType::Font
            )
            || is_tracker_blocked(url, self.block_trackers)
        {
            return None;
        }
        if self.extra_headers.read().await.keys().any(|name| {
            ["authorization", "cookie", "cache-control"].iter().any(|h| name.eq_ignore_ascii_case(h))
        }) {
            return None;
        }
        if request.sends_credentials_to(url)
            && !self.cookie_jar.get_cookie_header_in_context(url, SameSiteContext::SameSite).is_empty()
        {
            return None;
        }
        let cache = crate::shared_cache::shared_asset_cache().await?;
        let key = crate::shared_cache::shared_cache_key(
            url.as_str(),
            STEALTH_USER_AGENT,
            &format!("{:?}", request.resource_type),
            &format!("{:?}", request.credentials),
        );
        Some((cache, key))
    }

    async fn fetch_with_profile(
        &self,
        url: &Url,
        request: ResourceRequest,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_request(url, request, callbacks, "GET", None, None).await
    }

    /// Continue a navigation without changing another page's headers or pool.
    pub async fn fetch_navigation_request(
        &self, url: &Url, method: &str, body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>, callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_navigation_request_from_document(url, method, body, headers, None, callbacks).await
    }

    /// Fetch a navigation with an optional owning document, retaining it across redirects.
    pub async fn fetch_navigation_request_from_document(
        &self, url: &Url, method: &str, body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>, initiator: Option<&Url>,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        let request = initiator.map(ResourceRequest::navigation_from_document)
            .unwrap_or_else(ResourceRequest::navigation);
        self.fetch_request(url, request, callbacks, method, body, headers).await
    }

    async fn fetch_request(
        &self, url: &Url, request: ResourceRequest, callbacks: Option<&CallbackRegistry>,
        method: &str, mut body: Option<Vec<u8>>, mut request_headers: Option<HashMap<String, String>>,
    ) -> Result<Response, ObscuraNetError> {
        let mut method = wreq::Method::from_bytes(method.as_bytes())
            .map_err(|error| ObscuraNetError::Network(error.to_string()))?;
        validate_url(url, self.allow_private_network)?;
        validate_request_mode(&request, url)?;
        if url.scheme() == "file" {
            return fetch_file_url(url, request.max_response_bytes, self.allow_file_access).await;
        }

        let mut current_url = url.clone();

        if is_tracker_blocked(&current_url, self.block_trackers) {
            tracing::debug!("Blocked tracker: {}", current_url);
            return Ok(Response {
                status: 0,
                url: current_url,
                headers: HashMap::new(),
                body: Vec::new(),
                redirected_from: Vec::new(),
            });
        }

        let mut redirects = Vec::new();
        let mut redirect_tainted = false;
        let mut referrer = request.referrer.clone().or_else(|| request.initiator.clone());
        let mut request_callback_fired = false;

        // Follow up to 20 redirects (Fetch spec + the reqwest path): 0..=20 makes
        // 21 requests, so the 20th hop is followed and only the 21st fails.
        for _ in 0..=20 {
            validate_request_mode(&request, &current_url)?;
            let mut req = self.current_client().request(method.clone(), current_url.as_str());

            req = req
                .header("accept", request.accept())
                .header("sec-fetch-site", request_fetch_site(&request, &current_url, redirect_tainted))
                .header("sec-fetch-mode", request.mode.header_value())
                .header("sec-fetch-dest", request.destination());
            if request.mode == RequestMode::Navigate {
                req = req
                    .header("upgrade-insecure-requests", "1")
                    .header("sec-fetch-user", "?1");
            }
            let referer = request_referrer(referrer.as_ref(), &current_url);
            if let Some(referer) = &referer {
                req = req.header("referer", referer);
            }
            let request_origin = serialized_request_origin(&request, redirect_tainted);

            let cookie_header = if request.sends_credentials_to(&current_url) {
                self.cookie_jar.get_cookie_header_in_context(
                    &current_url,
                    same_site_context(
                        &request,
                        &current_url,
                        matches!(method, wreq::Method::GET | wreq::Method::HEAD),
                    ),
                )
            } else {
                String::new()
            };
            if !cookie_header.is_empty() {
                req = req.header("Cookie", &cookie_header);
            }

            let extra_headers = self.extra_headers.read().await;
            let supplied = request_headers.as_ref();
            let effective_headers = supplied.unwrap_or(&extra_headers);
            if let Some(ua) = effective_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v)
                .or(self.user_agent.as_ref()) {
                req = req.header("user-agent", ua.as_str());
            }
            for (k, v) in effective_headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent")) {
                if k.eq_ignore_ascii_case("origin") {
                    continue;
                }
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(origin) = request_origin_header(&request, &current_url, &request_origin, matches!(method, wreq::Method::GET | wreq::Method::HEAD)) {
                req = req.header("origin", origin);
            }

            let request_info = RequestInfo {
                url: current_url.clone(),
                method: method.to_string(),
                headers: effective_headers.clone(),
                resource_type: request.resource_type,
            };

            if let Some(bytes) = &body {
                if method == wreq::Method::POST && !effective_headers.keys().any(|name| name.eq_ignore_ascii_case("content-type")) {
                    req = req.header("content-type", "application/x-www-form-urlencoded");
                }
                req = req.body(bytes.clone());
            }
            drop(extra_headers);
            if !request_callback_fired {
                if let Some(callbacks) = callbacks {
                    callbacks.fire_request(&request_info).await;
                }
                request_callback_fired = true;
            }

            let in_flight = InFlightGuard::new(&self.in_flight);
            let (resp, _dial) = self
                .send_with_aia(req, &current_url, method == wreq::Method::GET)
                .await
                .map_err(|e| {
                    ObscuraNetError::Network(format!("{}: {}", current_url, error_chain(&e)))
                })?;

            let status = resp.status();
            validate_wreq_cors_response(
                &request,
                &current_url,
                &request_origin,
                resp.headers(),
            )?;

            if request.sends_credentials_to(&current_url) {
                for val in resp.headers().get_all("set-cookie") {
                    if let Ok(s) = val.to_str() {
                        self.cookie_jar.set_cookie(s, &current_url);
                    }
                }
            }

            let mut response_headers: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers().iter() {
                crate::client::merge_response_header(
                    &mut response_headers,
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                );
            }

            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location") {
                    let location_str = location.to_str().map_err(|_| {
                        ObscuraNetError::Network("Invalid redirect Location".into())
                    })?;
                    let next_url = current_url.join(location_str).map_err(|e| {
                        ObscuraNetError::Network(format!("Invalid redirect URL: {}", e))
                    })?;
                    validate_url(&next_url, self.allow_private_network)?;
                    validate_request_mode(&request, &next_url)?;
                    referrer = referer.as_deref().map(Url::parse).transpose()
                        .map_err(|error| ObscuraNetError::Network(format!("Invalid redirect referrer: {error}")))?;
                    redirect_tainted |=
                        redirect_taints_origin(&request, &current_url, &next_url);
                    if next_url.origin() != current_url.origin() {
                        if let Some(headers) = request_headers.as_mut() {
                            headers.retain(|name, _| !name.eq_ignore_ascii_case("authorization"));
                        }
                    }
                    redirects.push(current_url.clone());
                    current_url = next_url;
                    if (status.as_u16() == 303 && method != wreq::Method::GET && method != wreq::Method::HEAD)
                        || (matches!(status.as_u16(), 301 | 302) && method == wreq::Method::POST) {
                        method = wreq::Method::GET; body = None;
                        if let Some(headers) = request_headers.as_mut() {
                            headers.retain(|name, _| !matches!(name.to_ascii_lowercase().as_str(),
                                "content-type" | "content-encoding" | "content-language" | "content-location" | "content-length"));
                        }
                    }
                    continue;
                }
            }

            let body = read_wreq_body_limited(resp, &current_url, request.max_response_bytes)
                .await?;
            drop(in_flight);

            let response = Response {
                url: current_url,
                status: status.as_u16(),
                headers: response_headers,
                body,
                redirected_from: redirects,
            };
            if let Some(callbacks) = callbacks {
                callbacks.fire_response(&request_info, &response).await;
            }
            return Ok(response);
        }

        Err(ObscuraNetError::TooManyRedirects(url.to_string()))
    }

    /// One request with no redirect following, for scripted fetch()/XHR. The
    /// caller supplies the Fetch credentials decision for this redirect hop,
    /// while this method preserves the Chrome transport fingerprint.
    pub async fn send_single(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        send_cookies: bool,
        store_cookies: bool,
    ) -> Result<Response, ObscuraNetError> {
        self.send_single_with_context(
            method,
            url,
            headers,
            body,
            send_cookies.then_some(SameSiteContext::SameSite),
            store_cookies,
        )
        .await
    }

    /// One request with an explicit cookie site context. Scripted fetch/XHR
    /// uses this so Strict and Lax cookies cannot leak cross-site.
    pub async fn send_single_with_context(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
    ) -> Result<Response, ObscuraNetError> {
        let response = self.send_single_headers_with_context(
            method, url, headers, body, cookie_context, store_cookies, 64 * 1024 * 1024,
        ).await?;
        Ok(Response {
            url: url.clone(), status: response.status, headers: response.headers,
            body: response.body.await?, redirected_from: Vec::new(),
        })
    }

    /// Preserve request policy and cookie handling while deferring body reads.
    pub async fn send_single_headers_with_context(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
        max_body_bytes: usize,
    ) -> Result<StealthResponseHeaders, ObscuraNetError> {
        if is_tracker_blocked(url, self.block_trackers) {
            tracing::debug!("Blocked tracker: {}", url);
            return Ok(StealthResponseHeaders {
                status: 0,
                headers: HashMap::new(),
                body: Box::pin(async { Ok(Vec::new()) }),
            });
        }

        let req_method = method
            .parse::<wreq::Method>()
            .map_err(|e| ObscuraNetError::Network(format!("invalid method '{}': {}", method, e)))?;
        let mut req = self.current_client().request(req_method, url.as_str());

        if let Some(context) = cookie_context {
            let cookie_header = self.cookie_jar.get_cookie_header_in_context(url, context);
            if !cookie_header.is_empty() {
                req = req.header("cookie", &cookie_header);
            }
        }
        let extra_headers = self.extra_headers.read().await;
        if let Some(ua) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v)
            .or_else(|| extra_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("user-agent")).map(|(_, v)| v))
            .or(self.user_agent.as_ref()) {
            req = req.header("user-agent", ua.as_str());
        }
        for (k, v) in extra_headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent")) {
            req = req.header(k.as_str(), v.as_str());
        }
        drop(extra_headers);
        for (k, v) in headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent")) {
            req = req.header(k.as_str(), v.as_str());
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let in_flight = InFlightGuard::new(&self.in_flight);
        let (resp, dial) = self.send_with_aia(req, url, false).await.map_err(|e| {
            ObscuraNetError::Network(format!("{}: {}", url, error_chain(&e)))
        })?;

        let status = resp.status();
        if store_cookies {
            for val in resp.headers().get_all("set-cookie") {
                if let Ok(s) = val.to_str() {
                    self.cookie_jar.set_cookie(s, url);
                }
            }
        }
        let response_headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body_url = url.clone();
        Ok(StealthResponseHeaders {
            status: status.as_u16(),
            headers: response_headers,
            body: Box::pin(async move {
                let (_in_flight, _dial) = (in_flight, dial);
                read_wreq_body_limited(resp, &body_url, max_body_bytes).await
            }),
        })
    }

    pub async fn set_extra_headers(&self, headers: HashMap<String, String>) {
        *self.extra_headers.write().await = headers;
    }

    pub fn active_requests(&self) -> u32 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_network_idle(&self) -> bool {
        self.active_requests() == 0
    }
}

#[cfg(all(test, feature = "stealth"))]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;

    use super::{
        StealthHttpClient, is_tracker_blocked, send_get_with_connection_reset_retry,
        tracker_blocking_enabled,
    };
    use crate::client::{ObscuraNetError, SsrfGuardResolver};
    use crate::cookies::CookieJar;
    use wreq::dns::{Name, Resolve};

    #[tokio::test]
    async fn stealth_user_agent_override_has_one_wire_value_for_navigation_and_script_fetch() {
        for scripted in [false, true] {
            for override_mode in 0..if scripted { 3 } else { 2 } {
                let extra = override_mode > 0;
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let url = Url::parse(&format!("http://{}/",listener.local_addr().unwrap())).unwrap();
                let server = std::thread::spawn(move || {
                    let (mut socket,_) = listener.accept().unwrap();
                    let mut request=Vec::new();let mut bytes=[0;4096];
                    while !request.windows(4).any(|part|part==b"\r\n\r\n") {
                        let n=Read::read(&mut socket,&mut bytes).unwrap();assert!(n>0);request.extend_from_slice(&bytes[..n]);
                    }
                    Write::write_all(&mut socket,b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                    String::from_utf8(request).unwrap()
                });
                let client=StealthHttpClient::with_proxy(Arc::new(CookieJar::new()),None,true).with_user_agent(Some("TestingUA/1.0".into()));
                if extra {client.extra_headers.write().await.insert("user-agent".into(),"HeaderUA/2.0".into());}
                let request_headers = if override_mode == 2 { [("User-Agent".into(), "RequestUA/3.0".into())].into() } else { std::collections::HashMap::new() };
                let response=if scripted {client.send_single("GET",&url,&request_headers,&[],true,true).await.unwrap()}
                    else {client.fetch(&url).await.unwrap()};
                assert_eq!(response.status,200);
                let wire=server.join().unwrap();
                let agents=wire.lines().filter_map(|line|line.split_once(':')).filter(|(name,_)|name.eq_ignore_ascii_case("user-agent"))
                    .map(|(_,value)|value.trim()).collect::<Vec<_>>();
                assert_eq!(agents,vec![if override_mode == 2 {"RequestUA/3.0"} else if extra {"HeaderUA/2.0"} else {"TestingUA/1.0"}],"scripted={scripted}, override={override_mode}: {wire}");
            }
        }
    }

    // Mirrors client::ssrf_tests::resolver_blocks_hostname_that_resolves_to_loopback.
    // Both transports must agree: a host-string check alone cannot see that a
    // public name points inward, so the stealth client needs the same resolver.
    #[tokio::test]
    async fn stealth_resolver_blocks_hostname_that_resolves_to_loopback() {
        let resolver = SsrfGuardResolver::new(false);
        let res = resolver.resolve(Name::from("localtest.me")).await;
        assert!(res.is_err(), "localtest.me -> 127.0.0.1 must be blocked");
    }

    #[tokio::test]
    async fn stealth_resolver_does_not_block_public_host() {
        // Tolerate a no-network sandbox: only an actual SSRF rejection fails.
        let resolver = SsrfGuardResolver::new(false);
        match resolver.resolve(Name::from("example.com")).await {
            Ok(_) => {}
            Err(e) => assert!(
                !e.to_string().contains("SSRF blocked"),
                "example.com wrongly SSRF-blocked: {e}"
            ),
        }
    }

    const PLAIN_BODY: &str = "<!DOCTYPE html><html><body><p id=\"mark\">gzip ok</p></body></html>";

    #[test]
    fn tracker_blocking_environment_defaults_to_enabled() {
        for value in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("yes"),
            Some("on"),
            Some("invalid"),
        ] {
            assert!(
                tracker_blocking_enabled(value),
                "{value:?} must leave tracker blocking enabled"
            );
        }
        for value in [
            Some("0"), Some("false"), Some(" NO "), Some("off"), Some(" FALSE "),
        ] {
            assert!(
                !tracker_blocking_enabled(value),
                "{value:?} must disable tracker blocking"
            );
        }
    }

    // The stealth transport delegates file:// to the shared loader, so it
    // inherits the same opt-in instead of reading local files unconditionally.
    #[tokio::test]
    async fn stealth_client_reads_file_urls_only_when_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.html");
        std::fs::write(&path, "local-secret").unwrap();
        let url = Url::from_file_path(&path).unwrap();

        let mut client = StealthHttpClient::new(Arc::new(CookieJar::new()));
        assert!(client.fetch(&url).await.is_err());
        client.allow_file_access = true;
        assert_eq!(client.fetch(&url).await.unwrap().body, b"local-secret");
    }

    #[test]
    fn tracker_blocking_respects_host_and_setting() {
        let url = Url::parse("https://www.google-analytics.com/collect").unwrap();

        assert!(is_tracker_blocked(&url, true));
        assert!(!is_tracker_blocked(&url, false));
        assert!(!is_tracker_blocked(
            &Url::parse("https://example.com/").unwrap(), true,
        ));
        assert!(!is_tracker_blocked(
            &Url::parse("file:///tmp/page.html").unwrap(), true,
        ));
    }

    #[test]
    fn tracker_blocking_constructor_reads_environment() {
        let client = StealthHttpClient::new(Arc::new(CookieJar::new()));
        let expected = tracker_blocking_enabled(
            std::env::var("OBSCURA_BLOCK_TRACKERS").ok().as_deref(),
        );
        assert_eq!(client.block_trackers, expected);
    }

    async fn assert_tracker_blocking_request(scripted: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let mut client = StealthHttpClient::with_proxy(
            Arc::new(CookieJar::new()),
            Some(&proxy),
            true,
        );
        let url = Url::parse("http://www.google-analytics.com/collect").unwrap();
        let headers = std::collections::HashMap::new();

        client.block_trackers = true;
        let blocked = if scripted {
            client.send_single("GET", &url, &headers, &[], false, false)
                .await
        } else {
            client.fetch(&url).await
        }.expect("blocked tracker returns an empty response");
        assert_eq!(blocked.status, 0);
        assert!(blocked.body.is_empty());
        assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await.is_err());

        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await.expect("request reaches local proxy").unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0u8; 1024];
                let count = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                    .await.expect("request headers arrive").unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
            }
            assert!(String::from_utf8(request).unwrap().starts_with(
                "GET http://www.google-analytics.com/collect HTTP/1.1\r\n",
            ));
            stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await.unwrap();
        });

        client.block_trackers = false;
        let allowed = if scripted {
            client.send_single("GET", &url, &headers, &[], false, false)
                .await
        } else {
            client.fetch(&url).await
        }.expect("disabled blocking allows the request");
        assert_eq!(allowed.status, 200);
        assert_eq!(allowed.body, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tracker_blocking_navigation_request() {
        assert_tracker_blocking_request(false).await;
    }

    #[tokio::test]
    async fn tracker_blocking_scripted_request() {
        assert_tracker_blocking_request(true).await;
    }

    // gzip (level 9) of PLAIN_BODY, hardcoded so the fixture needs no
    // compression dependency. A wrong byte fails the assert below.
    const GZIP_BODY: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xb3, 0x51,
        0x74, 0xf1, 0x77, 0x0e, 0x89, 0x0c, 0x70, 0x55, 0xc8, 0x28, 0xc9, 0xcd,
        0xb1, 0xb3, 0x81, 0x90, 0x49, 0xf9, 0x29, 0x95, 0x76, 0x36, 0x05, 0x0a,
        0x99, 0x29, 0xb6, 0x4a, 0xb9, 0x89, 0x45, 0xd9, 0x4a, 0x76, 0xe9, 0x55,
        0x99, 0x05, 0x0a, 0xf9, 0xd9, 0x36, 0xfa, 0x05, 0x76, 0x36, 0xfa, 0x10,
        0x69, 0x7d, 0xb0, 0x5a, 0x00, 0x80, 0x3d, 0x1c, 0x5f, 0x41, 0x00, 0x00,
        0x00,
    ];

    fn reset_fixture(respond_after_reset: bool) -> (u16, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let attempts = if respond_after_reset { 2 } else { 1 };
            for attempt in 0..attempts {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut buf).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                }

                if attempt == 0 {
                    let socket = socket2::Socket::from(stream);
                    socket.set_linger(Some(Duration::ZERO)).unwrap();
                    drop(socket);
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
            attempts
        });
        (port, server)
    }

    #[tokio::test]
    async fn stealth_get_recovers_from_connection_reset() {
        let (port, server) = reset_fixture(true);
        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let response = send_get_with_connection_reset_retry(client.get(url.as_str()), &url)
            .await
            .expect("an idempotent GET should recover from one connection reset");

        assert_eq!(response.status(), wreq::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(server.join().unwrap(), 2);
    }

    #[tokio::test]
    async fn stealth_post_does_not_retry_connection_reset() {
        let (port, server) = reset_fixture(false);
        let client = StealthHttpClient {
            client: std::sync::RwLock::new((wreq::Client::builder().no_proxy().build().unwrap(), 0)),
            proxy_url: None,
            allow_private_network: true,
            allow_file_access: false,
            block_trackers: true,
            cookie_jar: Arc::new(CookieJar::new()),
            extra_headers: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            user_agent: None,
        };
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let error = client
            .send_single(
                "POST",
                &url,
                &std::collections::HashMap::new(),
                b"payload",
                false,
                false,
            )
            .await
            .expect_err("POST must not be retried after a connection reset");

        assert!(matches!(error, ObscuraNetError::Network(_)));
        assert_eq!(server.join().unwrap(), 1);
    }

    // See `navigation_accepts_a_folded_response_header` in client.rs: the
    // stealth transport must read a folded header as Chrome does.
    #[tokio::test]
    async fn stealth_client_accepts_a_folded_response_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\n  https://a.example\n  https://b.example\r\ncontent-length: 6\r\nconnection: close\r\n\r\nfolded";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

        let resp = client
            .fetch(&url)
            .await
            .expect("a folded header must not fail the response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text(), "folded");
    }

    #[tokio::test]
    async fn stealth_network_error_names_the_cause() {
        // A port nobody listens on: the message must say the connection was
        // refused instead of only "error sending request", and must not be a
        // Debug dump of the error structs.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let message = client.fetch(&url).await.expect_err("nothing listens").to_string();
        assert!(message.to_lowercase().contains("refused"), "{message}");
        assert!(!message.contains("source: Some("), "{message}");
    }

    /// Serve one `Content-Encoding: gzip` response on an ephemeral port.
    async fn gzip_fixture() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        GZIP_BODY.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(GZIP_BODY).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        port
    }

    // The emulation profile advertises gzip, so origins compress. Without the
    // decoder the raw gzip bytes reach the HTML parser as document text.
    #[tokio::test]
    async fn stealth_client_decodes_gzip_response() {
        let port = gzip_fixture().await;
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

        let resp = client.fetch(&url).await.expect("fixture must be reachable");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text(), PLAIN_BODY, "gzip body must be decompressed");
    }

    // #793: the opt-in must reach the DNS resolver. `validate_url` already
    // honours it for the localhost host, so a hostname target exercises the
    // resolver itself; before the fix the resolver was pinned to block and
    // refused loopback hostnames even with the flag set. Only the allowed
    // leg is asserted: CI sets OBSCURA_ALLOW_PRIVATE_NETWORK, which also
    // lifts the default block.
    #[tokio::test]
    async fn stealth_client_honors_allow_private_network_for_loopback_hostnames() {
        let port = gzip_fixture().await;
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://localhost:{port}/")).unwrap();

        let resp = client
            .fetch(&url)
            .await
            .expect("loopback hostname must be reachable with the opt-in");
        assert_eq!(resp.status, 200);
    }

    // The first request to an origin with no live connection dials alone; the rest wait for its headers, then run.
    #[tokio::test]
    async fn dial_gate_lets_one_request_dial_and_releases_the_rest_on_its_headers() {
        let url = Url::parse("https://dial-gate-test.invalid/").unwrap();
        let gate = super::dial_gate(None, &url);
        let mut scout = gate.enter().await;
        assert!(scout.scout.is_some(), "the first request must be the scout");

        let waiting = gate.clone();
        let waiter = tokio::spawn(async move { waiting.enter().await.scout.is_none() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "a second request must wait for the scout");

        scout.settle();
        assert!(waiter.await.unwrap(), "the waiter proceeds without dialing alone");
        assert!(gate.enter().await.scout.is_none(), "an origin with a running request is not gated");

        drop(scout);
        assert!(gate.enter().await.scout.is_some(), "an origin with no running request is gated again");
    }

    // Pages in one process share the wreq client, so a second page reuses the first page's connection.
    #[tokio::test]
    async fn pages_share_one_connection_pool() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0
                            || stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        for _ in 0..2 {
            let page = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
            assert_eq!(page.fetch(&url).await.expect("fixture must be reachable").status, 200);
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1, "both pages must reuse one connection");
    }
}
