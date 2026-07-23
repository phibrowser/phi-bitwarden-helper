// Phi Bitwarden Helper — socketpair protocol server.
//
// Wire-identical to Phi's Swift `BitwardenHelperClient` (and the Swift
// `BitwardenHelperServer` it mirrors): on startup the server sends a challenge
// frame over the inherited socketpair, reads the client's ack, then loops
// reading 4-byte big-endian length-prefixed JSON requests and writing framed
// JSON responses. Each request runs on its own thread and its response echoes
// the client's `request_id`, so replies may complete out of order and a slow
// `login` never blocks a concurrent `status`.
//
//   response envelope:
//     success -> {"ok": true,  "result": { … }, "request_id": "…"}
//     failure -> {"ok": false, "error": { "message": "…" }, "request_id": "…"}

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::engine::{
    Engine, EngineError, LookupCandidate, LookupOutcome, PersistedRecord, Query, VaultItem,
};

const MAX_FRAME: usize = 4 * 1024 * 1024;

extern "C" {
    fn getppid() -> i32;
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Exits the process when Phi (our parent) goes away — reparented to launchd,
/// so `getppid()` returns 1 — covering quit *and* crash. Also drives the engine's
/// session-timeout policy each tick with the current idle time, so a configured
/// idle timeout (1h / 4h) locks or logs out the vault.
fn spawn_lifecycle_monitor(last_activity: Arc<AtomicU64>, engine: Arc<dyn Engine>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        if unsafe { getppid() } <= 1 {
            std::process::exit(0);
        }
        let idle = now_secs().saturating_sub(last_activity.load(Ordering::Relaxed));
        engine.enforce_timeout(idle);
    });
}

/// Serves the single socketpair connection Phi handed us on fd 0. No peer
/// authentication is needed: the kernel guarantees the other end is the process
/// that spawned us — the socket has no name for anyone else to reach.
///
/// Challenge handshake first (a liveness/version check), then the request loop.
/// EOF or a read error means Phi closed its end (quit, crash, or teardown), so
/// we return and the process exits with it.
pub fn run(stream: UnixStream, engine: Arc<dyn Engine>) -> std::io::Result<()> {
    let last_activity = Arc::new(AtomicU64::new(now_secs()));
    spawn_lifecycle_monitor(Arc::clone(&last_activity), Arc::clone(&engine));

    let mut reader = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(stream));

    // Give the engine a channel to ask the app to persist/forget the session.
    // The helper owns no at-rest store; each record is serialized into a
    // `persist` event frame on this same socket and the app writes its Keychain.
    // Event writes take the response mutex, so they interleave safely with
    // replies. Best-effort: if the app's end is gone the request loop's next
    // read fails and we exit anyway.
    {
        let sink_writer = Arc::clone(&writer);
        engine.set_persist_sink(Box::new(move |record| {
            let session = persist_session_value(record);
            if let Ok(mut w) = sink_writer.lock() {
                let _ = write_frame(&mut w, &json!({ "event": "persist", "session": session }));
            }
        }));
    }

    let challenge = random_hex(16)?;
    write_frame(&mut writer.lock().unwrap(), &json!({ "challenge": challenge }))?;
    let ack = read_frame(&mut reader)?;
    if ack.get("challenge_response").and_then(Value::as_str) != Some(challenge.as_str()) {
        return Ok(()); // bad ack — refuse to serve
    }

    loop {
        let request = match read_frame(&mut reader) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        last_activity.store(now_secs(), Ordering::Relaxed);
        let engine = Arc::clone(&engine);
        let writer = Arc::clone(&writer);
        thread::spawn(move || {
            let mut response = dispatch(&request, engine.as_ref());
            if let Some(id) = request.get("request_id") {
                if let Some(envelope) = response.as_object_mut() {
                    envelope.insert("request_id".into(), id.clone());
                }
            }
            if let Ok(mut w) = writer.lock() {
                let _ = write_frame(&mut w, &response);
            }
        });
    }
}

fn dispatch(request: &Value, engine: &dyn Engine) -> Value {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    match handle(method, &params, engine) {
        Ok(result) => json!({ "ok": true, "result": result }),
        Err(e) => json!({ "ok": false, "error": { "message": e.to_string() } }),
    }
}

fn handle(method: &str, params: &Value, engine: &dyn Engine) -> Result<Value, EngineError> {
    match method {
        "status" => {
            let status = engine.status()?;
            let mut result = Map::new();
            result.insert("status".into(), Value::String(status.wire().to_string()));
            if let Some(account) = engine.account() {
                result.insert("account".into(), Value::String(account));
            }
            Ok(Value::Object(result))
        }
        "login" => {
            let email = params.get("email").and_then(Value::as_str).unwrap_or("");
            let master_password = params.get("masterPassword").and_then(Value::as_str).unwrap_or("");
            let two_factor = params.get("twoFactor").and_then(Value::as_str);
            // Optional non-default server (EU cloud / self-hosted). The client
            // computes the identity + api URLs per region; we just apply them.
            let server = params.get("server");
            let identity_url = server.and_then(|s| s.get("identityUrl")).and_then(Value::as_str);
            let api_url = server.and_then(|s| s.get("apiUrl")).and_then(Value::as_str);
            let timeout = params.get("timeout").and_then(Value::as_str).unwrap_or("");
            let action = params.get("action").and_then(Value::as_str).unwrap_or("");
            engine.login(
                email,
                master_password,
                two_factor,
                identity_url,
                api_url,
                timeout,
                action,
            )?;
            Ok(json!({}))
        }
        "restore" => {
            // The app re-establishes a session it restored from its own Keychain
            // (the helper reads no store). Same shape as `login`, with the
            // stored 2FA remember token in place of a fresh code; a missing
            // `masterPassword` means locked-restore.
            let email = params.get("email").and_then(Value::as_str).unwrap_or("");
            let master_password = params.get("masterPassword").and_then(Value::as_str);
            let two_factor_token = params.get("twoFactorToken").and_then(Value::as_str);
            let server = params.get("server");
            let identity_url = server.and_then(|s| s.get("identityUrl")).and_then(Value::as_str);
            let api_url = server.and_then(|s| s.get("apiUrl")).and_then(Value::as_str);
            let timeout = params.get("timeout").and_then(Value::as_str).unwrap_or("");
            let action = params.get("action").and_then(Value::as_str).unwrap_or("");
            let status = engine.restore(
                email,
                master_password,
                two_factor_token,
                identity_url,
                api_url,
                timeout,
                action,
            )?;
            Ok(json!({ "status": status.wire() }))
        }
        "setTimeout" => {
            let timeout = params.get("timeout").and_then(Value::as_str).unwrap_or("");
            let action = params.get("action").and_then(Value::as_str).unwrap_or("");
            engine.set_timeout(timeout, action);
            Ok(json!({}))
        }
        "unlock" => {
            let master_password = params.get("masterPassword").and_then(Value::as_str);
            // Fresh second-factor code for a 2FA account whose remember token
            // is absent/expired; normally omitted (the engine replays its
            // stored token).
            let two_factor = params.get("twoFactor").and_then(Value::as_str);
            engine.unlock(master_password, two_factor)?;
            Ok(json!({}))
        }
        "lock" => {
            engine.lock();
            Ok(json!({}))
        }
        "logout" => {
            engine.logout()?;
            Ok(json!({}))
        }
        "lookup" => {
            let query = parse_query(params)?;
            match engine.lookup(&query)? {
                LookupOutcome::Hit(hit) => Ok(json!({
                    "found": true,
                    "item": encode_item(&hit.item),
                    "matches": hit.matches,
                })),
                // Several items match: no secret is released. `found: false`
                // keeps an older client fail-safe (it reads plain not-found);
                // a current client reads `ambiguous` + the non-secret
                // candidates and asks for a narrowed query.
                LookupOutcome::Ambiguous(candidates) => Ok(json!({
                    "found": false,
                    "ambiguous": true,
                    "matches": candidates.len(),
                    "candidates": candidates
                        .iter()
                        .take(20)
                        .map(encode_candidate)
                        .collect::<Vec<_>>(),
                })),
                LookupOutcome::None => Ok(json!({ "found": false })),
            }
        }
        "getTotp" => {
            let query = parse_query(params)?;
            match engine.totp(&query)? {
                Some(totp) => Ok(json!({ "totp": totp })),
                None => Ok(json!({ "totp": "" })),
            }
        }
        other => Err(EngineError::Failure(format!("Unknown method: {other}"))),
    }
}

/// Blank query text is rejected here rather than matched: an empty search
/// needle would substring-match every item and turn a malformed request into
/// "first credential in the vault".
fn parse_query(params: &Value) -> Result<Query, EngineError> {
    let q = params
        .get("query")
        .ok_or_else(|| EngineError::Failure("Missing query".into()))?;
    if let Some(d) = q.get("domain").and_then(Value::as_str) {
        let d = d.trim();
        if d.is_empty() {
            return Err(EngineError::Failure("Empty domain in query".into()));
        }
        return Ok(Query::Domain {
            domain: d.to_string(),
            username: q
                .get("username")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    if let Some(id) = q.get("id").and_then(Value::as_str) {
        let id = id.trim();
        if id.is_empty() {
            return Err(EngineError::Failure("Empty id in query".into()));
        }
        return Ok(Query::Id(id.to_string()));
    }
    if let Some(s) = q.get("search").and_then(Value::as_str) {
        let s = s.trim();
        if s.is_empty() {
            return Err(EngineError::Failure("Empty search in query".into()));
        }
        return Ok(Query::Search(s.to_string()));
    }
    Err(EngineError::Failure("Empty query".into()))
}

/// Keys match Phi's Swift `BitwardenService.parseItem`. The totp field (the
/// raw seed) is deliberately NOT encoded — TOTP support is out for now, and
/// the seed must never cross to the app even on an explicit field ask.
fn encode_item(item: &VaultItem) -> Value {
    let mut m = Map::new();
    m.insert("credentialId".into(), Value::String(item.id.clone()));
    if !item.kind.is_empty() {
        m.insert("type".into(), Value::String(item.kind.clone()));
    }
    if !item.name.is_empty() {
        m.insert("name".into(), Value::String(item.name.clone()));
    }
    insert_opt(&mut m, "username", &item.username);
    insert_opt(&mut m, "password", &item.password);
    insert_opt(&mut m, "uri", &item.uri);
    insert_opt(&mut m, "notes", &item.notes);
    insert_opt(&mut m, "domain", &item.domain);
    // Type-specific fields of cards, identities, and SSH keys — already
    // wire-named by the engine, never overlapping the fixed keys above.
    for (key, value) in &item.typed {
        m.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(m)
}

fn insert_opt(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v.clone()));
    }
}

/// One ambiguous-lookup candidate: identity fields only, never a secret.
/// `type`/`name` let the caller tell apart items that have no username
/// (notes, cards, keys).
fn encode_candidate(candidate: &LookupCandidate) -> Value {
    let mut m = Map::new();
    m.insert("credentialId".into(), Value::String(candidate.id.clone()));
    if !candidate.kind.is_empty() {
        m.insert("type".into(), Value::String(candidate.kind.clone()));
    }
    if !candidate.name.is_empty() {
        m.insert("name".into(), Value::String(candidate.name.clone()));
    }
    insert_opt(&mut m, "username", &candidate.username);
    insert_opt(&mut m, "uri", &candidate.uri);
    insert_opt(&mut m, "domain", &candidate.domain);
    Value::Object(m)
}

/// Serializes a persist record for the `persist` event: `Some` → an object the
/// app stores (`{email, masterPassword?, server?}`), `None` → JSON null (clear).
/// Shape matches the `restore` request params so the app round-trips it.
fn persist_session_value(record: Option<PersistedRecord>) -> Value {
    let Some(r) = record else {
        return Value::Null;
    };
    let mut obj = Map::new();
    obj.insert("email".into(), Value::String(r.email));
    if let Some(p) = r.master_password {
        obj.insert("masterPassword".into(), Value::String(p));
    }
    if let Some(t) = r.two_factor_token {
        obj.insert("twoFactorToken".into(), Value::String(t));
    }
    if r.identity_url.is_some() || r.api_url.is_some() {
        let mut server = Map::new();
        insert_opt(&mut server, "identityUrl", &r.identity_url);
        insert_opt(&mut server, "apiUrl", &r.api_url);
        obj.insert("server".into(), Value::Object(server));
    }
    Value::Object(obj)
}

// MARK: - Framing

fn write_frame(stream: &mut UnixStream, value: &Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Value> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad frame length",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn random_hex(n: usize) -> std::io::Result<String> {
    let mut f = fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{LookupHit, VaultStatus};

    /// Engine stub whose lookup always reports two matching accounts.
    struct AmbiguousEngine;

    impl Engine for AmbiguousEngine {
        fn status(&self) -> Result<VaultStatus, EngineError> {
            Ok(VaultStatus::Unlocked)
        }
        fn account(&self) -> Option<String> {
            None
        }
        fn login(
            &self,
            _email: &str,
            _master_password: &str,
            _two_factor: Option<&str>,
            _identity_url: Option<&str>,
            _api_url: Option<&str>,
            _timeout: &str,
            _action: &str,
        ) -> Result<(), EngineError> {
            Err(EngineError::NotImplemented)
        }
        fn unlock(&self, _master_password: Option<&str>, _two_factor: Option<&str>)
            -> Result<(), EngineError> {
            Err(EngineError::NotImplemented)
        }
        fn lock(&self) {}
        fn logout(&self) -> Result<(), EngineError> {
            Err(EngineError::NotImplemented)
        }
        fn lookup(&self, _query: &Query) -> Result<LookupOutcome, EngineError> {
            Ok(LookupOutcome::Ambiguous(vec![
                LookupCandidate {
                    id: "id-1".into(),
                    kind: "login".into(),
                    name: "Example".into(),
                    username: Some("alice@example.com".into()),
                    uri: Some("https://example.com".into()),
                    domain: Some("example.com".into()),
                },
                LookupCandidate {
                    id: "id-2".into(),
                    kind: "note".into(),
                    name: "example note".into(),
                    username: None,
                    uri: None,
                    domain: Some("example.com".into()),
                },
            ]))
        }
        fn totp(&self, _query: &Query) -> Result<Option<String>, EngineError> {
            Err(EngineError::NotImplemented)
        }
    }

    /// The wire contract finding 5's fix rests on: an ambiguous lookup must
    /// carry NO item (and thus no secret), read as not-found to an older
    /// client, and expose only candidate identities.
    #[test]
    fn ambiguous_lookup_releases_no_item() {
        let engine = AmbiguousEngine;
        let result =
            handle("lookup", &json!({"query": {"domain": "example.com"}}), &engine).unwrap();
        assert_eq!(result["found"], json!(false));
        assert_eq!(result["ambiguous"], json!(true));
        assert_eq!(result["matches"], json!(2));
        assert!(result.get("item").is_none());
        let candidates = result["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 2);
        for candidate in candidates {
            assert!(candidate.get("password").is_none());
            assert!(candidate.get("notes").is_none());
            assert!(candidate.get("totp").is_none());
        }
        assert_eq!(candidates[0]["username"], json!("alice@example.com"));
        assert_eq!(candidates[1]["credentialId"], json!("id-2"));
        // Non-login candidates are identified by type + name instead.
        assert_eq!(candidates[1]["type"], json!("note"));
        assert_eq!(candidates[1]["name"], json!("example note"));
    }

    /// A non-login item rides the same envelope: its wire type and name are
    /// present and its type-specific fields land flat next to the fixed keys.
    #[test]
    fn typed_item_encodes_type_and_flat_fields() {
        let encoded = encode_item(&VaultItem {
            id: "id-3".into(),
            kind: "card".into(),
            name: "Visa".into(),
            typed: vec![
                ("number".into(), "4111111111111111".into()),
                ("code".into(), "123".into()),
                ("brand".into(), "Visa".into()),
            ],
            ..Default::default()
        });
        assert_eq!(encoded["credentialId"], json!("id-3"));
        assert_eq!(encoded["type"], json!("card"));
        assert_eq!(encoded["name"], json!("Visa"));
        assert_eq!(encoded["number"], json!("4111111111111111"));
        assert_eq!(encoded["code"], json!("123"));
        assert!(encoded.get("username").is_none());
    }

    /// A unique hit is unchanged by the ambiguity rework.
    #[test]
    fn unique_lookup_still_serves_the_item() {
        struct HitEngine;
        impl Engine for HitEngine {
            fn status(&self) -> Result<VaultStatus, EngineError> {
                Ok(VaultStatus::Unlocked)
            }
            fn account(&self) -> Option<String> {
                None
            }
            fn login(
                &self,
                _email: &str,
                _master_password: &str,
                _two_factor: Option<&str>,
                _identity_url: Option<&str>,
                _api_url: Option<&str>,
                _timeout: &str,
                _action: &str,
            ) -> Result<(), EngineError> {
                Err(EngineError::NotImplemented)
            }
            fn unlock(&self, _mp: Option<&str>, _tf: Option<&str>) -> Result<(), EngineError> {
                Err(EngineError::NotImplemented)
            }
            fn lock(&self) {}
            fn logout(&self) -> Result<(), EngineError> {
                Err(EngineError::NotImplemented)
            }
            fn lookup(&self, _query: &Query) -> Result<LookupOutcome, EngineError> {
                Ok(LookupOutcome::Hit(LookupHit {
                    item: VaultItem {
                        id: "id-1".into(),
                        username: Some("alice@example.com".into()),
                        password: Some("s3cret".into()),
                        ..Default::default()
                    },
                    matches: 1,
                }))
            }
            fn totp(&self, _query: &Query) -> Result<Option<String>, EngineError> {
                Err(EngineError::NotImplemented)
            }
        }
        let result =
            handle("lookup", &json!({"query": {"domain": "example.com"}}), &HitEngine).unwrap();
        assert_eq!(result["found"], json!(true));
        assert_eq!(result["matches"], json!(1));
        assert_eq!(result["item"]["password"], json!("s3cret"));
        assert!(result.get("ambiguous").is_none());
    }

    /// The persisted record round-trips the 2FA remember token (finding 6):
    /// it must ride the `persist` event in both restore shapes.
    #[test]
    fn persist_event_carries_two_factor_token() {
        let value = persist_session_value(Some(PersistedRecord {
            email: "a@b.c".into(),
            master_password: None,
            two_factor_token: Some("remember-me".into()),
            identity_url: None,
            api_url: None,
        }));
        assert_eq!(value["email"], json!("a@b.c"));
        assert_eq!(value["twoFactorToken"], json!("remember-me"));
        assert!(value.get("masterPassword").is_none());
    }

    #[test]
    fn parse_query_rejects_blank_text() {
        for params in [
            json!({"query": {"search": ""}}),
            json!({"query": {"search": "   "}}),
            json!({"query": {"domain": " "}}),
            json!({"query": {"id": ""}}),
            json!({"query": {}}),
            json!({}),
        ] {
            assert!(parse_query(&params).is_err(), "accepted: {params}");
        }
    }

    #[test]
    fn parse_query_trims_search() {
        match parse_query(&json!({"query": {"search": " github "}})) {
            Ok(Query::Search(s)) => assert_eq!(s, "github"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
