// Phi Bitwarden Helper — SDK-backed vault engine.
// Copyright (C) 2026 Phinomenon Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// Compiled only under `--features bitwarden-sdk`. Drives the pinned Bitwarden
// SDK (sdk-internal @ rust-v3.0.0). Login/sync/lock are wired against the SDK's
// async client. The helper owns NO at-rest store: the app persists the session
// in its own Keychain and re-establishes it via `restore` after the handshake,
// so a copy of this signed binary spawned by an attacker cannot restore a
// session on its own. State changes here emit a `PersistedRecord` through the
// persist sink for the app to store. Vault lookup + TOTP land in the next slice.

use std::io::Read;
use std::sync::{Arc, Mutex, Once};

use bitwarden_core::auth::login::{
    LoginError, PasswordLoginRequest, TwoFactorProvider, TwoFactorRequest,
};
use bitwarden_core::{init_host_platform_info, ClientSettings, DeviceType, HostPlatformInfo};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_sync::{SyncClientExt, SyncRequest};
use bitwarden_vault::{
    Cipher, CipherRepromptType, CipherType, CipherView, LoginUriView, UriMatchType, VaultClientExt,
};

use crate::engine::{
    Engine, EngineError, LookupCandidate, LookupHit, LookupOutcome, PersistSink, PersistedRecord,
    Query, VaultItem, VaultStatus,
};

/// When the current unlocked session ends. Drives both idle enforcement and
/// what the persisted record encodes for the next start.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeoutKind {
    OneHour,
    FourHours,
    OnSystemLock,
    OnBrowserRestart,
    Never,
}

impl TimeoutKind {
    fn parse(s: &str) -> Self {
        match s {
            "oneHour" => TimeoutKind::OneHour,
            "fourHours" => TimeoutKind::FourHours,
            "onSystemLock" => TimeoutKind::OnSystemLock,
            "never" => TimeoutKind::Never,
            // Default matches the settings default shown to the user.
            _ => TimeoutKind::OnBrowserRestart,
        }
    }

    /// Idle threshold in seconds, for the time-based kinds only.
    fn idle_secs(self) -> Option<u64> {
        match self {
            TimeoutKind::OneHour => Some(3600),
            TimeoutKind::FourHours => Some(4 * 3600),
            _ => None,
        }
    }
}

/// What ending the session does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeoutAction {
    Lock,
    LogOut,
}

impl TimeoutAction {
    fn parse(s: &str) -> Self {
        match s {
            "logOut" => TimeoutAction::LogOut,
            _ => TimeoutAction::Lock,
        }
    }
}

/// Version reported via the `Bitwarden-Client-Version` header. The identity
/// server refuses logins without it ("required to prevent encryption errors")
/// and compares it against the account's minimum supported client version, so
/// it must track a current official client release — NOT this helper's own
/// version. Revisit when bumping the SDK pin.
const BITWARDEN_CLIENT_VERSION: &str = "2026.6.0";

/// Settings for every SDK client this engine builds. `PasswordManagerClient`
/// sources its HTTP headers from these settings — NOT from the
/// `init_host_platform_info` global, which only feeds `GlobalClient` — so the
/// client-version header and device identifier must be supplied here.
///
/// `identity_url`/`api_url` override the server for EU-cloud or self-hosted
/// logins; the SDK routes identity + api calls to whatever these hold (there is
/// no built-in region switch). Empty/`None` keeps the default US cloud.
fn client_settings(identity_url: Option<&str>, api_url: Option<&str>) -> ClientSettings {
    let mut settings = ClientSettings {
        user_agent: format!("PhiBitwardenHelper/{}", env!("CARGO_PKG_VERSION")),
        device_type: DeviceType::MacOsCLI,
        device_identifier: Some(device_identifier()),
        bitwarden_client_version: Some(BITWARDEN_CLIENT_VERSION.to_string()),
        bitwarden_package_type: Some("cli".to_string()),
        ..ClientSettings::default()
    };
    if let Some(url) = identity_url.filter(|u| !u.is_empty()) {
        settings.identity_url = url.to_string();
    }
    if let Some(url) = api_url.filter(|u| !u.is_empty()) {
        settings.api_url = url.to_string();
    }
    settings
}

/// Stable per-user device identifier, persisted on first use. Bitwarden keys
/// its known-device tracking (and new-device verification emails) on this, so
/// it must survive helper restarts — a fresh one per process would make every
/// login look like a brand-new device.
///
/// Lives as `bitwarden-device-id` inside the browser's own data folder
/// (`PHI_BROWSER_DATA_DIR`, passed by the app when it spawns the helper), so
/// the helper does not own a folder of its own. Standalone runs (dev probes)
/// without that variable fall back to a helper-named folder.
fn device_identifier() -> String {
    let dir = std::env::var("PHI_BROWSER_DATA_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}/Library/Application Support/PhiBitwardenHelper",
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
            )
        });
    let path = format!("{dir}/bitwarden-device-id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim();
        if !existing.is_empty() {
            return existing.to_string();
        }
    }
    let id = random_uuid_v4();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&path, &id);
    id
}

fn random_uuid_v4() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

struct Inner {
    /// The logged-in client, or None when logged out / locked. login_password
    /// also initializes user crypto, so a present client means an unlocked vault.
    client: Option<PasswordManagerClient>,
    email: Option<String>,
    /// Decrypted vault items cached at login/restore, searched by `lookup`.
    /// The pinned SDK registers no cipher sync handler, so `sync()`'s data is
    /// not auto-persisted — we decrypt the sync response ourselves and hold the
    /// views here (this process is already the vault-secret boundary).
    ciphers: Vec<CipherView>,
    /// Master password held in RAM while unlocked, so the persisted record can be
    /// rewritten as the timeout policy changes without another login. Cleared on
    /// lock/logout.
    master_password: Option<String>,
    /// Server-issued 2FA remember token (see `PersistedRecord`). Survives lock —
    /// it is device trust, not vault-key material — and is what lets `unlock`/
    /// `restore` re-login a 2FA account without a fresh code. Cleared on logout.
    two_factor_token: Option<String>,
    identity_url: Option<String>,
    api_url: Option<String>,
    /// True when an account identity is known but no in-memory key is loaded —
    /// the *locked* state. `unlock` re-establishes the vault from the password.
    locked: bool,
    timeout: TimeoutKind,
    action: TimeoutAction,
}

impl Inner {
    fn new() -> Self {
        Inner {
            client: None,
            email: None,
            ciphers: Vec::new(),
            master_password: None,
            two_factor_token: None,
            identity_url: None,
            api_url: None,
            locked: false,
            timeout: TimeoutKind::OnBrowserRestart,
            action: TimeoutAction::Lock,
        }
    }

    /// The record to persist for the current account + policy: unlocked-restore
    /// (store password), locked-restore (identity only), or forget (`None`).
    /// Pure — the caller emits the result through the persist sink after
    /// dropping the lock; the helper itself writes no store.
    fn persist_record(&self) -> Option<PersistedRecord> {
        let email = self.email.as_ref()?;
        // On browser restart the session must not silently return unlocked.
        let store_password = match (self.timeout, self.action) {
            (TimeoutKind::OnBrowserRestart, TimeoutAction::LogOut) => return None,
            (TimeoutKind::OnBrowserRestart, TimeoutAction::Lock) => false,
            // Every other kind (never / idle / system-lock) keeps a restart
            // unlocked — restart is not their trigger.
            _ => true,
        };
        Some(PersistedRecord {
            email: email.clone(),
            master_password: if store_password {
                self.master_password.clone()
            } else {
                None
            },
            // Device trust rides along in both restore shapes; without it a
            // 2FA account's next start cannot re-login at all.
            two_factor_token: self.two_factor_token.clone(),
            identity_url: self.identity_url.clone(),
            api_url: self.api_url.clone(),
        })
    }
}

pub struct SdkEngine {
    rt: tokio::runtime::Runtime,
    inner: Arc<Mutex<Inner>>,
    /// Sink the protocol server installs so state changes here can ask the app
    /// to persist/forget the session (the helper keeps no store of its own).
    persist_sink: Mutex<Option<PersistSink>>,
}

/// Runs the password login + initial vault sync and returns the unlocked client
/// together with its decrypted vault items and — when the login's
/// `TwoFactorRequest` asked `remember: true` — the server-issued 2FA remember
/// token to replay on later logins. Shared by interactive login, unlock, and
/// startup restore so all take the identical, verified path.
async fn perform_login(
    email: &str,
    master_password: &str,
    two_factor: Option<TwoFactorRequest>,
    new_device_otp: Option<&str>,
    identity_url: Option<&str>,
    api_url: Option<&str>,
) -> Result<(PasswordManagerClient, Vec<CipherView>, Option<String>), EngineError> {
    let client = PasswordManagerClient::new(Some(client_settings(identity_url, api_url)));

    let result = client
        .0
        .auth()
        .login_password(&PasswordLoginRequest {
            email: email.to_string(),
            password: master_password.to_string(),
            two_factor,
            new_device_otp: new_device_otp.filter(|c| !c.is_empty()).map(str::to_string),
        })
        .await
        .map_err(login_error)?;

    if result.two_factor.is_some() {
        return Err(EngineError::TwoFactorRequired);
    }
    let remember_token = result.two_factor_token;

    // Pull the vault down and decrypt it now so lookups have data.
    let ciphers = sync_and_decrypt(&client)
        .await
        .map_err(|e| EngineError::Failure(format!("Login succeeded but sync failed: {e}")))?;
    Ok((client, ciphers, remember_token))
}

/// Translates the SDK's login failures into the engine's own errors. Only the
/// ones a client must *act* on get a variant of their own — everything else
/// keeps the SDK's message, which the sign-in sheet shows verbatim.
fn login_error(error: LoginError) -> EngineError {
    match error {
        LoginError::NewDeviceVerificationRequired => EngineError::NewDeviceVerificationRequired,
        LoginError::InvalidNewDeviceOtp => EngineError::InvalidNewDeviceOtp,
        other => EngineError::Failure(other.to_string()),
    }
}

/// A `TwoFactorRequest` replaying a stored remember token (no fresh code, no
/// new token requested), or None when no token is held.
fn remember_request(token: &Option<String>) -> Option<TwoFactorRequest> {
    token.as_ref().map(|t| TwoFactorRequest {
        token: t.clone(),
        provider: TwoFactorProvider::Remember,
        remember: false,
    })
}

/// Syncs the vault and decrypts every cipher to a `CipherView`. Items that fail
/// to convert or decrypt are skipped, not fatal. Inlined decrypt loop so the
/// api-model type stays inferred (no extra dependency to name it).
async fn sync_and_decrypt(client: &PasswordManagerClient) -> Result<Vec<CipherView>, EngineError> {
    let sync = client
        .0
        .sync()
        .sync(SyncRequest {
            exclude_subdomains: None,
        })
        .await
        .map_err(|e| EngineError::Failure(e.to_string()))?;

    let ciphers_client = client.0.vault().ciphers();
    let mut ciphers = Vec::new();
    for model in sync.ciphers.unwrap_or_default() {
        if let Ok(cipher) = Cipher::try_from(model) {
            if let Ok(view) = ciphers_client.decrypt(cipher).await {
                ciphers.push(view);
            }
        }
    }
    Ok(ciphers)
}

/// True if `view` satisfies `query` (case-insensitive).
fn cipher_matches(view: &CipherView, query: &Query) -> bool {
    match query {
        Query::Id(id) => view.id.as_ref().map(|i| i.to_string()).as_deref() == Some(id.as_str()),
        Query::Search(s) => {
            let needle = s.to_lowercase();
            // An empty needle would substring-match every item. The protocol
            // layer already rejects blank searches; this keeps the engine safe
            // for any future caller that doesn't.
            if needle.is_empty() {
                return false;
            }
            if view.name.to_lowercase().contains(&needle) {
                return true;
            }
            let username_hit = view
                .login
                .as_ref()
                .and_then(|l| l.username.as_deref())
                .map_or(false, |u| u.to_lowercase().contains(&needle));
            username_hit
                || login_uris(view)
                    .iter()
                    .any(|u| u.to_lowercase().contains(&needle))
        }
        Query::Domain { domain, username } => {
            let domain = domain.trim().to_lowercase();
            if domain.is_empty() {
                return false;
            }
            let uri_hit = view
                .login
                .as_ref()
                .and_then(|l| l.uris.as_ref())
                .map_or(false, |uris| uris.iter().any(|u| uri_matches_domain(u, &domain)));
            if !uri_hit {
                return false;
            }
            match username {
                Some(wanted) => view
                    .login
                    .as_ref()
                    .and_then(|l| l.username.as_deref())
                    .map_or(false, |u| u.eq_ignore_ascii_case(wanted.trim())),
                None => true,
            }
        }
    }
}

/// Login URIs of a cipher as plain strings.
fn login_uris(view: &CipherView) -> Vec<String> {
    view.login
        .as_ref()
        .and_then(|l| l.uris.as_ref())
        .map(|uris| uris.iter().filter_map(|u| u.uri.clone()).collect())
        .unwrap_or_default()
}

/// Applies a stored URI's Bitwarden match rule against the queried domain
/// (https://bitwarden.com/help/uri-match-detection/).
///
/// The query carries a domain, not the page URL, so the URL-shaped rules
/// (`Exact`, `StartsWith`, `RegularExpression`) are evaluated against the
/// site-root URLs that domain stands in for (`root_urls`). A rule that needs a
/// deeper URL to be satisfied therefore under-matches — the credential simply
/// isn't served — but none of them can match more broadly than the user's rule
/// allows. `Never` is the user's explicit opt-out and never matches.
fn uri_matches_domain(stored: &LoginUriView, domain: &str) -> bool {
    let Some(uri) = stored.uri.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
        return false;
    };
    // A URI without an explicit rule uses the vault's default match detection,
    // which is base-domain matching.
    match stored.r#match.unwrap_or(UriMatchType::Domain) {
        UriMatchType::Domain => host_matches(uri, domain),
        UriMatchType::Host => host_port_of(uri).as_deref() == Some(domain),
        UriMatchType::Exact => {
            let stored = uri.to_lowercase();
            let stored = stored.trim_end_matches('/');
            root_urls(domain).iter().any(|url| stored == url.trim_end_matches('/'))
        }
        UriMatchType::StartsWith => {
            let stored = uri.to_lowercase();
            root_urls(domain).iter().any(|url| url.starts_with(&stored))
        }
        UriMatchType::RegularExpression => regex::RegexBuilder::new(uri)
            .case_insensitive(true)
            .build()
            .map_or(false, |re| root_urls(domain).iter().any(|url| re.is_match(url))),
        UriMatchType::Never => false,
    }
}

/// The site-root URLs a domain query stands in for when a match rule is
/// defined against the full page URL. Scheme'd forms only: real URLs always
/// carry a scheme, so a bare-domain candidate would let e.g. a `StartsWith`
/// URI of "exam" match where Bitwarden's own clients never would.
fn root_urls(domain: &str) -> [String; 2] {
    [format!("https://{domain}/"), format!("http://{domain}/")]
}

/// The `Domain` (default) match rule: the stored URI's host and the queried
/// domain share a base domain — equal, or one a dot-suffix of the other with
/// the parent side carrying at least two labels.
///
/// The two-label floor keeps a bare public suffix ("com", "co") from matching
/// every host beneath it and handing back an arbitrary credential. This is a
/// dependency-free stand-in for true eTLD+1 / public-suffix matching — the
/// SDK's inherited `Cargo.lock` forbids adding a PSL crate (§6.1), so a real
/// public-suffix list is future work; the two-label floor covers the dangerous
/// single-label case. A stored URI with no parseable host is not domain-matched
/// at all (use `search` for those) rather than matched by a loose substring
/// test that "github.com" would satisfy inside "github.com.evil.example".
fn host_matches(uri: &str, domain: &str) -> bool {
    let Some(host) = host_of(uri) else {
        return false;
    };
    if host == domain {
        return true;
    }
    (domain.contains('.') && host.ends_with(&format!(".{domain}")))
        || (host.contains('.') && domain.ends_with(&format!(".{host}")))
}

/// Extracts lowercase `host[:port]` from a URI, tolerating a missing scheme.
/// The `Host` rule matches on hostname *and* port, so unlike `host_of` this
/// keeps an explicit port: a URI stored for "example.com:8443" must not match
/// a query for plain "example.com".
fn host_port_of(uri: &str) -> Option<String> {
    let trimmed = uri.trim();
    let after = match trimmed.split_once("://") {
        Some((_, rest)) => rest,
        None => trimmed,
    };
    let host_port = after
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if host_port.is_empty() {
        None
    } else {
        Some(host_port)
    }
}

/// Extracts the lowercase host from a URI, tolerating a missing scheme.
fn host_of(uri: &str) -> Option<String> {
    let trimmed = uri.trim();
    let after = match trimmed.split_once("://") {
        Some((_, rest)) => rest,
        None => trimmed,
    };
    let host = after
        .split(|c| c == '/' || c == '?' || c == ':')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// The wire item type a cipher is served as, or None for the types the
/// credential surface does not expose (bank account, driver's license,
/// passport — this SDK fork's extras, not part of Bitwarden's standard item
/// set). A login cipher with no login payload is malformed and unserved.
fn item_kind(view: &CipherView) -> Option<&'static str> {
    match view.r#type {
        CipherType::Login if view.login.is_some() => Some("login"),
        CipherType::SecureNote => Some("note"),
        CipherType::Card => Some("card"),
        CipherType::Identity => Some("identity"),
        CipherType::SshKey => Some("sshKey"),
        _ => None,
    }
}

/// Appends a present, non-empty type-specific field under its wire key.
fn push_field(typed: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        typed.push((key.to_string(), v.to_string()));
    }
}

/// Projects a decrypted cipher into the wire `VaultItem`.
///
/// An organization can withhold secret viewing on a shared item
/// (`view_password == false`); handing a secret to an agent is a view, so such
/// an item serves its identity but keeps the hidden fields back — the login
/// password and TOTP seed, a card's number and code, an SSH private key
/// (mirroring the hide-passwords collection permission, which covers them all).
fn to_vault_item(view: &CipherView, query: &Query) -> VaultItem {
    let login = view.login.as_ref();
    let uri = login_uris(view).into_iter().next();
    let domain = match query {
        Query::Domain { domain, .. } => Some(domain.clone()),
        _ => uri.as_deref().and_then(host_of),
    };
    let mut typed: Vec<(String, String)> = Vec::new();
    match view.r#type {
        CipherType::Card => {
            if let Some(card) = view.card.as_ref() {
                push_field(&mut typed, "cardholderName", card.cardholder_name.as_deref());
                push_field(&mut typed, "brand", card.brand.as_deref());
                if view.view_password {
                    push_field(&mut typed, "number", card.number.as_deref());
                    push_field(&mut typed, "code", card.code.as_deref());
                }
                push_field(&mut typed, "expMonth", card.exp_month.as_deref());
                push_field(&mut typed, "expYear", card.exp_year.as_deref());
            }
        }
        CipherType::Identity => {
            if let Some(identity) = view.identity.as_ref() {
                push_field(&mut typed, "title", identity.title.as_deref());
                push_field(&mut typed, "firstName", identity.first_name.as_deref());
                push_field(&mut typed, "middleName", identity.middle_name.as_deref());
                push_field(&mut typed, "lastName", identity.last_name.as_deref());
                push_field(&mut typed, "address1", identity.address1.as_deref());
                push_field(&mut typed, "address2", identity.address2.as_deref());
                push_field(&mut typed, "address3", identity.address3.as_deref());
                push_field(&mut typed, "city", identity.city.as_deref());
                push_field(&mut typed, "state", identity.state.as_deref());
                push_field(&mut typed, "postalCode", identity.postal_code.as_deref());
                push_field(&mut typed, "country", identity.country.as_deref());
                push_field(&mut typed, "company", identity.company.as_deref());
                push_field(&mut typed, "email", identity.email.as_deref());
                push_field(&mut typed, "phone", identity.phone.as_deref());
                push_field(&mut typed, "ssn", identity.ssn.as_deref());
                push_field(&mut typed, "passportNumber", identity.passport_number.as_deref());
                push_field(&mut typed, "licenseNumber", identity.license_number.as_deref());
            }
        }
        CipherType::SshKey => {
            if let Some(key) = view.ssh_key.as_ref() {
                if view.view_password {
                    push_field(&mut typed, "privateKey", Some(key.private_key.as_str()));
                }
                push_field(&mut typed, "publicKey", Some(key.public_key.as_str()));
                push_field(&mut typed, "fingerprint", Some(key.fingerprint.as_str()));
            }
        }
        _ => {}
    }
    VaultItem {
        id: view.id.as_ref().map(|i| i.to_string()).unwrap_or_default(),
        kind: item_kind(view).unwrap_or("login").to_string(),
        name: view.name.clone(),
        // An identity carries a username of its own; it shares the login's slot
        // since an item is only ever one type.
        username: login
            .and_then(|l| l.username.clone())
            .or_else(|| view.identity.as_ref().and_then(|i| i.username.clone())),
        password: login.and_then(|l| l.password.clone()).filter(|_| view.view_password),
        totp: login.and_then(|l| l.totp.clone()).filter(|_| view.view_password),
        uri,
        notes: view.notes.clone(),
        domain,
        typed,
    }
}

/// Projects a matching cipher into its non-secret identity for an ambiguous
/// lookup — enough to narrow the query (id or username), never a secret.
fn to_candidate(view: &CipherView, query: &Query) -> LookupCandidate {
    let login = view.login.as_ref();
    let uri = login_uris(view).into_iter().next();
    let domain = match query {
        Query::Domain { domain, .. } => Some(domain.clone()),
        _ => uri.as_deref().and_then(host_of),
    };
    LookupCandidate {
        id: view.id.as_ref().map(|i| i.to_string()).unwrap_or_default(),
        kind: item_kind(view).unwrap_or("login").to_string(),
        name: view.name.clone(),
        username: login.and_then(|l| l.username.clone()),
        uri,
        domain,
    }
}

impl SdkEngine {
    pub fn new() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // Feeds `GlobalClient` construction inside the SDK, should any code
            // path build one; the per-client headers come from
            // `client_settings()`. Keep the two consistent (default server —
            // the per-login override only affects the login client).
            init_host_platform_info(HostPlatformInfo::from(&client_settings(None, None)));
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        SdkEngine {
            rt,
            inner: Arc::new(Mutex::new(Inner::new())),
            persist_sink: Mutex::new(None),
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hands `record` to the app for persistence: `Some` stores it, `None`
    /// forgets it. No-op until the protocol server installs the sink. Never
    /// call while holding the `inner` lock — compute the record, drop the lock,
    /// then emit.
    fn emit_persist(&self, record: Option<PersistedRecord>) {
        if let Some(sink) = self.persist_sink.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            sink(record);
        }
    }

    /// Current decrypted ciphers for a lookup/TOTP call. Snapshots the client
    /// under the lock, then syncs OFF the lock — never hold the mutex across
    /// the network round trip — so edits made since login are reflected. On a
    /// transient sync failure, falls back to the cached snapshot ONLY when one
    /// exists; with an empty cache the failure is surfaced, since answering
    /// from it would misreport every item as missing (`not_found`).
    fn fresh_ciphers(&self) -> Result<Vec<CipherView>, EngineError> {
        let client = {
            let inner = self.lock_inner();
            match &inner.client {
                Some(c) => PasswordManagerClient(c.0.clone()),
                None => return Err(EngineError::LoggedOut),
            }
        };
        match self.rt.block_on(sync_and_decrypt(&client)) {
            Ok(fresh) => {
                self.lock_inner().ciphers = fresh.clone();
                Ok(fresh)
            }
            Err(e) => {
                let cached = self.lock_inner().ciphers.clone();
                if cached.is_empty() {
                    Err(EngineError::Failure(format!("Vault sync failed: {e}")))
                } else {
                    Ok(cached)
                }
            }
        }
    }
}

impl Engine for SdkEngine {
    fn status(&self) -> Result<VaultStatus, EngineError> {
        // Restore is a normal request the app sends right after the handshake and
        // awaits before anything else, so by the time a `status` arrives the
        // session is already re-established — no wait needed here.
        let inner = self.lock_inner();
        Ok(if inner.client.is_some() {
            VaultStatus::Unlocked
        } else if inner.locked {
            VaultStatus::Locked
        } else {
            VaultStatus::LoggedOut
        })
    }

    fn account(&self) -> Option<String> {
        self.lock_inner().email.clone()
    }

    fn login(
        &self,
        email: &str,
        master_password: &str,
        two_factor: Option<&str>,
        new_device_otp: Option<&str>,
        identity_url: Option<&str>,
        api_url: Option<&str>,
        timeout: &str,
        action: &str,
    ) -> Result<(), EngineError> {
        // A typed code asks the server to remember this device (`remember:
        // true` → the success response carries a remember token), so later
        // unlocks/restores can re-login without a second factor.
        let two_factor = two_factor.filter(|t| !t.is_empty()).map(|token| TwoFactorRequest {
            token: token.to_string(),
            provider: TwoFactorProvider::Authenticator,
            remember: true,
        });

        let (client, ciphers, remember_token) = self.rt.block_on(perform_login(
            email,
            master_password,
            two_factor,
            new_device_otp,
            identity_url,
            api_url,
        ))?;

        let record = {
            let mut inner = self.lock_inner();
            inner.client = Some(client);
            inner.email = Some(email.to_string());
            inner.ciphers = ciphers;
            inner.master_password = Some(master_password.to_string());
            if remember_token.is_some() {
                inner.two_factor_token = remember_token;
            }
            inner.identity_url = identity_url.filter(|u| !u.is_empty()).map(str::to_string);
            inner.api_url = api_url.filter(|u| !u.is_empty()).map(str::to_string);
            inner.locked = false;
            inner.timeout = TimeoutKind::parse(timeout);
            inner.action = TimeoutAction::parse(action);
            inner.persist_record()
        };
        // Persist per the policy (unlocked-restore / locked-restore / forget).
        self.emit_persist(record);
        Ok(())
    }

    fn unlock(
        &self,
        master_password: Option<&str>,
        two_factor: Option<&str>,
        new_device_otp: Option<&str>,
    ) -> Result<(), EngineError> {
        // Already unlocked (live or restored) — nothing to do.
        if self.lock_inner().client.is_some() {
            return Ok(());
        }
        // Locked: re-establish the vault from the master password (typed, or
        // released by biometric/PIN on the app side).
        let (email, stored_token, identity_url, api_url) = {
            let inner = self.lock_inner();
            match &inner.email {
                Some(email) if inner.locked => (
                    email.clone(),
                    inner.two_factor_token.clone(),
                    inner.identity_url.clone(),
                    inner.api_url.clone(),
                ),
                _ => return Err(EngineError::Failure("Log in to unlock.".to_string())),
            }
        };
        let password = master_password
            .filter(|p| !p.is_empty())
            .ok_or_else(|| EngineError::Failure("Master password required.".to_string()))?;

        // Second factor for the re-login: a freshly typed code wins (and mints
        // a new remember token); otherwise replay the stored remember token.
        // With neither, a 2FA account's login fails with "Two-step code
        // required." and the unlock UI offers the code field.
        let two_factor = two_factor
            .filter(|t| !t.is_empty())
            .map(|token| TwoFactorRequest {
                token: token.to_string(),
                provider: TwoFactorProvider::Authenticator,
                remember: true,
            })
            .or_else(|| remember_request(&stored_token));

        let (client, ciphers, remember_token) = self.rt.block_on(perform_login(
            &email,
            password,
            two_factor,
            new_device_otp,
            identity_url.as_deref(),
            api_url.as_deref(),
        ))?;

        let record = {
            let mut inner = self.lock_inner();
            inner.client = Some(client);
            inner.ciphers = ciphers;
            inner.master_password = Some(password.to_string());
            if remember_token.is_some() {
                inner.two_factor_token = remember_token;
            }
            inner.locked = false;
            inner.persist_record()
        };
        self.emit_persist(record);
        Ok(())
    }

    fn lock(&self) {
        // Drop the in-memory key and cached vault, but keep the account identity
        // so the vault can be unlocked (not re-logged-in). The persisted record
        // is downgraded to locked-restore so a browser restart also stays locked.
        let record = {
            let mut inner = self.lock_inner();
            inner.client = None;
            inner.ciphers = Vec::new();
            inner.master_password = None;
            inner.locked = inner.email.is_some();
            inner.email.as_ref().map(|email| PersistedRecord {
                email: email.clone(),
                master_password: None,
                // Locking seals the vault, not the device trust: the remember
                // token stays so the eventual unlock can re-login a 2FA
                // account without a fresh code.
                two_factor_token: inner.two_factor_token.clone(),
                identity_url: inner.identity_url.clone(),
                api_url: inner.api_url.clone(),
            })
        };
        // Only rewrite when an account remains; a bare lock with no account keeps
        // whatever the app already holds (there is nothing to downgrade).
        if record.is_some() {
            self.emit_persist(record);
        }
    }

    fn logout(&self) -> Result<(), EngineError> {
        // Deliberate "forget me": drop the persisted session and all state,
        // keeping only the current timeout policy.
        {
            let mut inner = self.lock_inner();
            let (timeout, action) = (inner.timeout, inner.action);
            *inner = Inner::new();
            inner.timeout = timeout;
            inner.action = action;
        }
        self.emit_persist(None);
        Ok(())
    }

    fn set_timeout(&self, timeout: &str, action: &str) {
        let record = {
            let mut inner = self.lock_inner();
            inner.timeout = TimeoutKind::parse(timeout);
            inner.action = TimeoutAction::parse(action);
            // Bring the persisted restart behavior in line with the new policy.
            inner.persist_record()
        };
        self.emit_persist(record);
    }

    fn restore(
        &self,
        email: &str,
        master_password: Option<&str>,
        two_factor_token: Option<&str>,
        identity_url: Option<&str>,
        api_url: Option<&str>,
        timeout: &str,
        action: &str,
    ) -> Result<VaultStatus, EngineError> {
        let identity = identity_url.filter(|u| !u.is_empty()).map(str::to_string);
        let api = api_url.filter(|u| !u.is_empty()).map(str::to_string);
        let token = two_factor_token.filter(|t| !t.is_empty()).map(str::to_string);
        let timeout_kind = TimeoutKind::parse(timeout);
        let action_kind = TimeoutAction::parse(action);

        // No stored password → locked-restore: identity known, vault sealed;
        // the user unlocks with their master password. The remember token is
        // kept so that unlock can re-login a 2FA account.
        let Some(password) = master_password.filter(|p| !p.is_empty()) else {
            let mut inner = self.lock_inner();
            inner.client = None;
            inner.ciphers = Vec::new();
            inner.master_password = None;
            inner.two_factor_token = token;
            inner.email = Some(email.to_string());
            inner.identity_url = identity;
            inner.api_url = api;
            inner.locked = true;
            inner.timeout = timeout_kind;
            inner.action = action_kind;
            return Ok(VaultStatus::Locked);
        };

        // Stored password → silent re-login into the unlocked state, replaying
        // the remember token for 2FA accounts. A failure (password changed,
        // revoked, remember token expired) propagates so the app drops its
        // now-stale Keychain record. Deliberately no persist emission — the
        // app already holds exactly this record.
        // No code to offer here — a restore runs before any UI exists. If the
        // server has forgotten this device the error propagates and the app
        // drops its stale record, sending the user back through sign-in.
        let (client, ciphers, remember_token) = self.rt.block_on(perform_login(
            email,
            password,
            remember_request(&token),
            None,
            identity.as_deref(),
            api.as_deref(),
        ))?;

        let mut inner = self.lock_inner();
        inner.client = Some(client);
        inner.email = Some(email.to_string());
        inner.ciphers = ciphers;
        inner.master_password = Some(password.to_string());
        inner.two_factor_token = remember_token.or(token);
        inner.identity_url = identity;
        inner.api_url = api;
        inner.locked = false;
        inner.timeout = timeout_kind;
        inner.action = action_kind;
        Ok(VaultStatus::Unlocked)
    }

    fn set_persist_sink(&self, sink: PersistSink) {
        *self.persist_sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    }

    fn enforce_timeout(&self, idle_secs: u64) {
        let (timeout, action, unlocked) = {
            let inner = self.lock_inner();
            (inner.timeout, inner.action, inner.client.is_some())
        };
        if !unlocked {
            return;
        }
        if let Some(threshold) = timeout.idle_secs() {
            if idle_secs >= threshold {
                match action {
                    TimeoutAction::Lock => self.lock(),
                    TimeoutAction::LogOut => {
                        let _ = self.logout();
                    }
                }
            }
        }
    }

    fn lookup(&self, query: &Query) -> Result<LookupOutcome, EngineError> {
        let ciphers = self.fresh_ciphers()?;
        // The credential surface serves the standard vault item set — logins,
        // secure notes, cards, identities, SSH keys — but never a trashed or
        // archived item. A domain query still reaches only logins: it matches
        // through login URIs (`cipher_matches`), which the other types do not
        // have, so an autofill-shaped query can never pull a note or key.
        let matched: Vec<&CipherView> = ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none() && c.archived_date.is_none())
            .filter(|c| item_kind(c).is_some())
            .filter(|c| cipher_matches(c, query))
            .collect();
        // Master-password re-prompt cannot be satisfied over this protocol
        // (the app's approval prompt is a click, not a password check), so a
        // protected item is refused loudly — neither served in bypass nor
        // silently hidden, which would misreport it as absent.
        let (servable, protected): (Vec<_>, Vec<_>) = matched
            .into_iter()
            .partition(|c| c.reprompt == CipherRepromptType::None);
        match servable.as_slice() {
            [] if !protected.is_empty() => Err(EngineError::Failure(
                "The matching item requires Bitwarden's master password re-prompt, \
                 which this credential surface does not support."
                    .to_string(),
            )),
            [] => Ok(LookupOutcome::None),
            [only] => Ok(LookupOutcome::Hit(LookupHit {
                item: to_vault_item(only, query),
                matches: 1,
            })),
            // Several servable items match: refuse to pick one. Releasing "the
            // first" would hand out an arbitrary account's secret and only
            // then report the ambiguity — by which point the wrong plaintext
            // has already crossed the boundary. Return the candidates'
            // non-secret identities so the caller can narrow the query.
            many => Ok(LookupOutcome::Ambiguous(
                many.iter().map(|c| to_candidate(c, query)).collect(),
            )),
        }
    }

    fn totp(&self, _query: &Query) -> Result<Option<String>, EngineError> {
        // Deliberately unimplemented for now: releasing a live 2FA code to an
        // agent collapses both factors behind one approval prompt. The seed is
        // likewise never exposed (encode_item drops it).
        Err(EngineError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(u: &str, m: Option<UriMatchType>) -> LoginUriView {
        LoginUriView {
            uri: Some(u.to_string()),
            r#match: m,
            uri_checksum: None,
        }
    }

    #[test]
    fn default_rule_is_base_domain() {
        assert!(uri_matches_domain(&uri("https://example.com/login", None), "example.com"));
        assert!(uri_matches_domain(&uri("https://app.example.com", None), "example.com"));
        // Reverse direction: stored base domain, queried subdomain.
        assert!(uri_matches_domain(&uri("https://example.com", None), "www.example.com"));
        // Label-aligned, never a substring test.
        assert!(!uri_matches_domain(&uri("https://evil-example.com", None), "example.com"));
        assert!(!uri_matches_domain(&uri("https://github.com.evil.example", None), "github.com"));
        // A bare public suffix must not match every host beneath it.
        assert!(!uri_matches_domain(&uri("https://example.com", None), "com"));
    }

    #[test]
    fn host_rule_is_exact_host_and_port() {
        let host = Some(UriMatchType::Host);
        assert!(uri_matches_domain(&uri("https://app.example.com/x", host), "app.example.com"));
        assert!(!uri_matches_domain(&uri("https://app.example.com", host), "example.com"));
        assert!(!uri_matches_domain(&uri("https://example.com:8443", host), "example.com"));
        assert!(uri_matches_domain(&uri("https://example.com:8443", host), "example.com:8443"));
    }

    #[test]
    fn exact_rule_matches_site_root_only() {
        let exact = Some(UriMatchType::Exact);
        assert!(uri_matches_domain(&uri("https://example.com", exact), "example.com"));
        assert!(uri_matches_domain(&uri("https://example.com/", exact), "example.com"));
        assert!(!uri_matches_domain(&uri("https://example.com/login", exact), "example.com"));
        assert!(!uri_matches_domain(&uri("https://sub.example.com", exact), "example.com"));
    }

    #[test]
    fn starts_with_rule() {
        let sw = Some(UriMatchType::StartsWith);
        assert!(uri_matches_domain(&uri("https://exam", sw), "example.com"));
        assert!(uri_matches_domain(&uri("https://example.com", sw), "example.com"));
        // Deeper than the site root: unknowable from a domain query — no match.
        assert!(!uri_matches_domain(&uri("https://example.com/app", sw), "example.com"));
        // Real URLs carry a scheme; a schemeless prefix never matches one.
        assert!(!uri_matches_domain(&uri("exam", sw), "example.com"));
    }

    #[test]
    fn regex_rule() {
        let re = Some(UriMatchType::RegularExpression);
        let pattern = r"^https://(www\.)?example\.com/";
        assert!(uri_matches_domain(&uri(pattern, re), "example.com"));
        assert!(uri_matches_domain(&uri(pattern, re), "www.example.com"));
        assert!(!uri_matches_domain(&uri(pattern, re), "app.example.com"));
        // An invalid pattern matches nothing rather than failing open.
        assert!(!uri_matches_domain(&uri("(", re), "example.com"));
    }

    #[test]
    fn never_rule_never_matches() {
        assert!(!uri_matches_domain(&uri("https://example.com", Some(UriMatchType::Never)), "example.com"));
    }

    #[test]
    fn blank_uri_never_matches() {
        assert!(!uri_matches_domain(&uri("  ", None), "example.com"));
        let no_uri = LoginUriView {
            uri: None,
            r#match: None,
            uri_checksum: None,
        };
        assert!(!uri_matches_domain(&no_uri, "example.com"));
    }

    /// Minimal decrypted cipher for projection tests, built through serde so
    /// the test does not have to spell out every SDK field.
    fn test_cipher(patch: serde_json::Value) -> CipherView {
        let mut base = serde_json::json!({
            "collectionIds": [],
            "name": "Item",
            "type": 1,
            "favorite": false,
            "reprompt": 0,
            "organizationUseTotp": false,
            "edit": true,
            "viewPassword": true,
            "creationDate": "2026-01-01T00:00:00Z",
            "revisionDate": "2026-01-01T00:00:00Z",
        });
        base.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        serde_json::from_value(base).expect("test cipher must deserialize")
    }

    #[test]
    fn every_standard_item_type_is_served() {
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 1, "login": {}}))), Some("login"));
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 2, "secureNote": {"type": 0}}))), Some("note"));
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 3, "card": {}}))), Some("card"));
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 4, "identity": {}}))), Some("identity"));
        assert_eq!(
            item_kind(&test_cipher(serde_json::json!({"type": 5,
                "sshKey": {"privateKey": "PK", "publicKey": "pub", "fingerprint": "fp"}}))),
            Some("sshKey")
        );
        // A login with no payload, and this fork's extra types, are not served.
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 1}))), None);
        assert_eq!(item_kind(&test_cipher(serde_json::json!({"type": 6}))), None);
    }

    #[test]
    fn search_matches_a_note_by_name_but_domain_does_not() {
        let note = test_cipher(serde_json::json!({
            "type": 2, "secureNote": {"type": 0}, "name": "testnote", "notes": "the body"
        }));
        assert!(cipher_matches(&note, &Query::Search("testnote".into())));
        // A domain query matches through login URIs, which a note has none of.
        assert!(!cipher_matches(&note, &Query::Domain {
            domain: "testnote".into(),
            username: None
        }));
        let item = to_vault_item(&note, &Query::Search("testnote".into()));
        assert_eq!(item.kind, "note");
        assert_eq!(item.name, "testnote");
        assert_eq!(item.notes.as_deref(), Some("the body"));
    }

    #[test]
    fn card_serves_wire_named_fields_with_hidden_gating() {
        let base = serde_json::json!({
            "type": 3, "name": "Visa",
            "card": {"cardholderName": "A. Person", "brand": "Visa",
                     "number": "4111111111111111", "expMonth": "4",
                     "expYear": "2030", "code": "123"}
        });
        let field = |item: &VaultItem, k: &str| {
            item.typed.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
        };
        let item = to_vault_item(&test_cipher(base.clone()), &Query::Search("visa".into()));
        assert_eq!(item.kind, "card");
        assert_eq!(field(&item, "number").as_deref(), Some("4111111111111111"));
        assert_eq!(field(&item, "code").as_deref(), Some("123"));
        assert_eq!(field(&item, "expMonth").as_deref(), Some("4"));

        // The hide-passwords permission withholds the hidden fields (number,
        // code), not the card's identity.
        let mut hidden = base;
        hidden.as_object_mut().unwrap().insert("viewPassword".into(), serde_json::json!(false));
        let item = to_vault_item(&test_cipher(hidden), &Query::Search("visa".into()));
        assert!(field(&item, "number").is_none());
        assert!(field(&item, "code").is_none());
        assert_eq!(field(&item, "brand").as_deref(), Some("Visa"));
    }

    #[test]
    fn ssh_key_serves_private_key_only_when_viewable() {
        let base = serde_json::json!({
            "type": 5, "name": "deploy key",
            "sshKey": {"privateKey": "PRIVATE", "publicKey": "ssh-ed25519 AAAA",
                       "fingerprint": "SHA256:abc"}
        });
        let item = to_vault_item(&test_cipher(base.clone()), &Query::Search("deploy".into()));
        assert_eq!(item.kind, "sshKey");
        assert!(item.typed.iter().any(|(k, v)| k == "privateKey" && v == "PRIVATE"));

        let mut hidden = base;
        hidden.as_object_mut().unwrap().insert("viewPassword".into(), serde_json::json!(false));
        let item = to_vault_item(&test_cipher(hidden), &Query::Search("deploy".into()));
        assert!(!item.typed.iter().any(|(k, _)| k == "privateKey"));
        assert!(item.typed.iter().any(|(k, _)| k == "publicKey"));
    }

    #[test]
    fn identity_username_shares_the_login_slot() {
        let identity = test_cipher(serde_json::json!({
            "type": 4, "name": "Me",
            "identity": {"firstName": "Ada", "lastName": "L",
                         "username": "ada", "ssn": "123-45-6789"}
        }));
        let item = to_vault_item(&identity, &Query::Search("me".into()));
        assert_eq!(item.kind, "identity");
        assert_eq!(item.username.as_deref(), Some("ada"));
        assert!(item.typed.iter().any(|(k, v)| k == "ssn" && v == "123-45-6789"));
        // The username rides the fixed slot, never duplicated in `typed`.
        assert!(!item.typed.iter().any(|(k, _)| k == "username"));
    }
}
