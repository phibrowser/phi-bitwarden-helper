// Phi Bitwarden Helper — vault engine seam.
//
// The protocol server depends only on the `Engine` trait; the stub engine
// (default build) and the SDK-backed engine (behind the `bitwarden-sdk`
// feature) implement it. This mirrors the Swift helper's `VaultEngine` seam so
// the two implementations stay recognizably the same.

use std::fmt;

/// Authentication/lock state of the vault. Wire strings match what Phi's Swift
/// client (`BitwardenService.parseStatus`) expects.
#[derive(Clone, Copy, Debug)]
pub enum VaultStatus {
    NotInstalled,
    NotConfigured,
    LoggedOut,
    Locked,
    Unlocked,
}

impl VaultStatus {
    pub fn wire(self) -> &'static str {
        match self {
            VaultStatus::NotInstalled => "notInstalled",
            VaultStatus::NotConfigured => "notConfigured",
            VaultStatus::LoggedOut => "loggedOut",
            VaultStatus::Locked => "locked",
            VaultStatus::Unlocked => "unlocked",
        }
    }
}

/// A credential query. Exactly one variant. A domain query may carry a
/// username to disambiguate between several accounts on the same site.
#[derive(Clone, Debug)]
pub enum Query {
    Domain {
        domain: String,
        username: Option<String>,
    },
    Id(String),
    Search(String),
}

/// A decrypted vault item reduced to the fields the credential surface exposes.
/// `kind` is the wire item type (`login` / `note` / `card` / `identity` /
/// `sshKey`; empty reads as login for wire compatibility). `typed` carries the
/// type-specific fields of cards, identities, and SSH keys as already
/// wire-named (key, value) pairs — the login fields keep their dedicated slots.
#[derive(Clone, Debug, Default)]
pub struct VaultItem {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub domain: Option<String>,
    pub typed: Vec<(String, String)>,
}

/// A successful lookup: the single item the query resolved to. `matches` is
/// kept for wire compatibility and is always 1 — a query matching several
/// servable items yields `LookupOutcome::Ambiguous`, never a hit.
#[derive(Clone, Debug)]
pub struct LookupHit {
    pub item: VaultItem,
    pub matches: usize,
}

/// The non-secret identity of one matching item, returned when a query is
/// ambiguous so the caller can narrow it (by username or id). Structurally
/// incapable of carrying a secret: no password/totp/notes field exists.
/// `kind`/`name` identify non-login items, which have no username to go by.
#[derive(Clone, Debug)]
pub struct LookupCandidate {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub domain: Option<String>,
}

/// Outcome of a lookup. A secret is released only through `Hit`, and a hit
/// requires the query to have matched exactly one servable item: several
/// matches come back as `Ambiguous` with candidate identities instead, so the
/// engine never picks an arbitrary account on the caller's behalf (the wrong
/// secret would already have crossed the boundary by the time anyone could
/// notice the ambiguity).
#[derive(Clone, Debug)]
pub enum LookupOutcome {
    None,
    Hit(LookupHit),
    Ambiguous(Vec<LookupCandidate>),
}

/// The session record the *app* persists on the helper's behalf. The helper no
/// longer owns any at-rest store: an attacker who spawned the signed helper
/// binary with their own socketpair could otherwise make it restore a Keychain
/// session and serve lookups. Custody now lives in the app's Keychain (scoped
/// to the app's code signature, which the helper binary does not satisfy); the
/// helper only decides *what* to persist and emits it through `PersistSink`.
///
/// `master_password` present means "unlocked-restore" (silent re-login on the
/// next start); absent means "locked-restore" (identity known, vault sealed).
///
/// `two_factor_token` is the server-issued 2FA remember token (requested with
/// `remember: true` at login). It rides along in BOTH restore shapes: it is
/// device trust, not vault-key material — without it every unlock/restore of a
/// 2FA account is a fresh login the server refuses for lack of a second
/// factor. Bitwarden's own clients store it in plain local storage; here it
/// shares the app's Keychain custody.
#[derive(Clone, Debug)]
pub struct PersistedRecord {
    pub email: String,
    pub master_password: Option<String>,
    pub two_factor_token: Option<String>,
    pub identity_url: Option<String>,
    pub api_url: Option<String>,
}

/// Installed by the protocol server so the engine can ask the app to persist a
/// session (`Some`) or forget it (`None`). The server serializes the record
/// into a `persist` event frame on the socketpair; the app writes its Keychain.
pub type PersistSink = Box<dyn Fn(Option<PersistedRecord>) + Send + Sync>;

/// A failed operation. The variants above `Failure` are the ones a client must
/// *act* on rather than merely display — each carries a stable `code()` the
/// protocol puts on the wire beside the message, so the sign-in UI can ask for
/// exactly what the server is missing.
#[derive(Debug)]
pub enum EngineError {
    NotImplemented,
    Locked,
    LoggedOut,
    NotFound,
    /// The account has a second factor and this login offered neither a fresh
    /// code nor remembered device trust.
    TwoFactorRequired,
    /// New-device login protection: the server does not recognize this
    /// device's identifier, has emailed a one-time code, and refuses every
    /// login from here until one arrives. Retry carrying `new_device_otp`.
    NewDeviceVerificationRequired,
    /// The `new_device_otp` sent with the last attempt was wrong or expired;
    /// the server has emailed a fresh code.
    InvalidNewDeviceOtp,
    Failure(String),
}

impl EngineError {
    /// Machine-readable tag for the errors a client branches on; `None` means
    /// "just display the message". These wire strings are matched by Phi's
    /// Swift client (`BitwardenService.ClientError.helperError`).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            EngineError::TwoFactorRequired => Some("twoFactorRequired"),
            EngineError::NewDeviceVerificationRequired => Some("newDeviceVerificationRequired"),
            EngineError::InvalidNewDeviceOtp => Some("invalidNewDeviceOtp"),
            _ => None,
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NotImplemented => write!(f, "Not implemented in this build."),
            EngineError::Locked => write!(f, "The vault is locked."),
            EngineError::LoggedOut => write!(f, "Not logged in."),
            EngineError::NotFound => write!(f, "No matching item."),
            EngineError::TwoFactorRequired => write!(f, "Two-step code required."),
            EngineError::NewDeviceVerificationRequired => write!(
                f,
                "New device verification required. Enter the code emailed to you."
            ),
            EngineError::InvalidNewDeviceOtp => {
                write!(f, "That verification code is invalid or has expired.")
            }
            EngineError::Failure(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// Vault operations the protocol server dispatches to. Synchronous — each
/// connection is served on its own thread, so blocking is fine; the SDK engine
/// bridges its async calls internally.
pub trait Engine: Send + Sync {
    fn status(&self) -> Result<VaultStatus, EngineError>;
    /// Display account identifier (e.g. email) when known.
    fn account(&self) -> Option<String>;

    /// `identity_url`/`api_url` target a non-default server (EU cloud or a
    /// self-hosted instance); both `None` means the default US cloud.
    /// `timeout`/`action` are the session-timeout policy wire strings (see
    /// `set_timeout`); they decide what survives across restarts.
    /// `new_device_otp` is the one-time code the server emails when it does not
    /// recognize this device (see `EngineError::NewDeviceVerificationRequired`);
    /// omitted on the first attempt, which is what triggers that email.
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
    ) -> Result<(), EngineError>;
    /// Re-establish the vault from a locked state. `master_password` is the
    /// user's password (typed, or released by biometric/PIN on the app side).
    /// `two_factor` is a freshly typed second-factor code for accounts whose
    /// remember token has expired (engines that hold a valid remember token
    /// need no code). `new_device_otp` is as in `login`: an unlock is a
    /// re-login, so a device the server has forgotten must verify again here.
    fn unlock(
        &self,
        master_password: Option<&str>,
        two_factor: Option<&str>,
        new_device_otp: Option<&str>,
    ) -> Result<(), EngineError>;
    fn lock(&self);
    fn logout(&self) -> Result<(), EngineError>;

    /// Re-establish a session the app restored from *its* Keychain and sent us
    /// right after the handshake (the helper reads no store of its own). With a
    /// `master_password` the vault comes back unlocked; without one it comes
    /// back locked (identity known, sealed). Deliberately does NOT persist — the
    /// app already holds this record. `timeout`/`action` set the session policy
    /// so idle enforcement and later persists match it. Default: unsupported.
    fn restore(
        &self,
        _email: &str,
        _master_password: Option<&str>,
        _two_factor_token: Option<&str>,
        _identity_url: Option<&str>,
        _api_url: Option<&str>,
        _timeout: &str,
        _action: &str,
    ) -> Result<VaultStatus, EngineError> {
        Err(EngineError::NotImplemented)
    }

    /// Install the sink the engine uses to ask the app to persist/forget the
    /// session (see `PersistSink`). Default no-op — the stub has nothing to
    /// persist.
    fn set_persist_sink(&self, _sink: PersistSink) {}

    fn lookup(&self, query: &Query) -> Result<LookupOutcome, EngineError>;
    fn totp(&self, query: &Query) -> Result<Option<String>, EngineError>;

    /// Update the session-timeout policy on the running session. `timeout` is one
    /// of `oneHour|fourHours|onSystemLock|onBrowserRestart|never`, `action` is
    /// `lock|logOut`. Default no-op (the stub has no session).
    fn set_timeout(&self, _timeout: &str, _action: &str) {}

    /// Called periodically by the lifecycle monitor with the seconds since the
    /// last request; an engine applies its idle timeout here. Default no-op.
    fn enforce_timeout(&self, _idle_secs: u64) {}
}

/// Placeholder engine used by the default build. Reports `notConfigured` and
/// refuses every operation with a clean error, so the socket, framing, and
/// Phi's client can be exercised without any real vault.
pub struct StubEngine;

impl StubEngine {
    pub fn new() -> Self {
        StubEngine
    }
}

impl Engine for StubEngine {
    fn status(&self) -> Result<VaultStatus, EngineError> {
        Ok(VaultStatus::NotConfigured)
    }
    fn account(&self) -> Option<String> {
        None
    }
    fn login(
        &self,
        _email: &str,
        _master_password: &str,
        _two_factor: Option<&str>,
        _new_device_otp: Option<&str>,
        _identity_url: Option<&str>,
        _api_url: Option<&str>,
        _timeout: &str,
        _action: &str,
    ) -> Result<(), EngineError> {
        Err(EngineError::NotImplemented)
    }
    fn unlock(
        &self,
        _master_password: Option<&str>,
        _two_factor: Option<&str>,
        _new_device_otp: Option<&str>,
    ) -> Result<(), EngineError> {
        Err(EngineError::NotImplemented)
    }
    fn lock(&self) {}
    fn logout(&self) -> Result<(), EngineError> {
        Err(EngineError::NotImplemented)
    }
    fn lookup(&self, _query: &Query) -> Result<LookupOutcome, EngineError> {
        Err(EngineError::NotImplemented)
    }
    fn totp(&self, _query: &Query) -> Result<Option<String>, EngineError> {
        Err(EngineError::NotImplemented)
    }
}
