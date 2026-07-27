//! In-process mock Console for CLI unit tests — the Rust analogue of the Python
//! `conftest` fixtures. Register canned responses per request path, then point a
//! Console fetcher's `console_url` at [`MockConsole::base_url`].
//!
//! No external dependency: a tiny `std` HTTP/1.1 server (the same `TcpListener`
//! pattern as the OIDC callback in `commands::auth`). The serving thread lives
//! for the test binary's lifetime (the listener is moved into it); tests are
//! short-lived, so the leaked thread and port are harmless.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

use serde_json::{json, Value};

use crate::commands::{cvm, key, profile};
use crate::session::{Entity, Session};

/// A fake, already-authenticated [`Session`] for tests that call Console
/// fetchers — not issued by a real login, all fields are filler. Only
/// `access_token` matters (it becomes the bearer header); `expires_at` is far
/// in the future so it always reads as valid, and there is no refresh token.
/// Entity id carried by [`fake_authenticated_session`] — the one the profile
/// list path is built from, so [`MockConsole::list_profiles`] targets the same
/// route the CLI requests.
pub(crate) const FAKE_ENTITY_ID: &str = "entity-1";

pub(crate) fn fake_authenticated_session() -> Session {
    Session {
        access_token: "token".into(),
        refresh_token: None,
        user_id: "user-1".into(),
        email: "user@example.com".into(),
        entity: Entity {
            id: FAKE_ENTITY_ID.into(),
            name: "Example".into(),
        },
        expires_at: chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc),
        refresh_expires_at: None,
    }
}

/// A [`ResolvedConfig`](crate::config::ResolvedConfig) pointed at `mock`, with a
/// valid session already written to its (temp) config dir. The fixture for
/// driving whole commands (`alias::run`) against the mock Console.
pub(crate) fn authenticated_config(mock: &MockConsole) -> crate::config::ResolvedConfig {
    let dir = std::env::temp_dir().join(format!("concrete-cmd-test-{}", uuid::Uuid::new_v4()));
    crate::session::write_atomic(&dir, &fake_authenticated_session()).expect("write session");
    crate::config::ResolvedConfig::resolve(crate::config::ConfigOverrides {
        config_dir: Some(dir),
        console_url: Some(mock.base_url().to_string()),
        ..Default::default()
    })
}

/// One pre-registered HTTP reply the mock Console returns for a given path:
/// status code, an optional ETag header (some CLI readers require it), and the
/// JSON body.
#[derive(Clone)]
struct Reply {
    status: u16,
    etag: Option<String>,
    body: String,
}

/// The output a test wants a resource GET to simulate: the resource is present
/// (`200` with its body) or absent (`404`).
pub(crate) enum Presence {
    Present,
    Absent,
}

/// A throwaway Console reachable at [`base_url`](Self::base_url). Each method
/// mirrors a real Console endpoint; the test picks the output it should return.
pub(crate) struct MockConsole {
    base_url: String,
    // What to answer, per path. Read outside-in:
    //   Arc     -> shared between the test and the serving thread
    //   Mutex   -> one accessor at a time (thread-safe)
    //   HashMap -> path -> reply to send back
    replies: Arc<Mutex<HashMap<String, Reply>>>,
}

impl MockConsole {
    /// Constructor: bind an OS-chosen free port on localhost, spawn a
    /// background thread that answers requests from the `replies` table, and
    /// return the handle. Register endpoints on it, then point the code under
    /// test at [`base_url`](Self::base_url).
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock console");
        let port = listener.local_addr().expect("mock console addr").port();
        let replies: Arc<Mutex<HashMap<String, Reply>>> = Arc::new(Mutex::new(HashMap::new()));
        let served = Arc::clone(&replies);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                serve(stream, &served);
            }
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            replies,
        }
    }

    /// Base URL to pass as `console_url` to the code under test.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    // --- Console endpoints (mirror the real routes; the test picks the output) --

    /// `GET /api/v1/cvms/{id}`.
    pub(crate) fn get_cvm(&self, id: &str, presence: Presence) {
        self.get_resource(cvm::cvm_path(id), presence, cvm_body(id));
    }

    /// `POST /api/v1/cvms/{id}/actions/{stop|start}` — a synchronous lifecycle
    /// action that echoes the updated Cvm plus an ETag (read via
    /// `read_with_etag`).
    pub(crate) fn cvm_lifecycle_action(&self, id: &str, action: &str) {
        self.reply_found(&cvm::cvm_action_path(id, action), cvm_body(id));
    }

    /// `POST /api/v1/cvms/{id}/actions/terminate` — an async teardown that
    /// returns an accepted `Operation` envelope. The CLI polls it, but
    /// `--no-wait` returns right after submit, so a minimal `running` envelope
    /// is enough to drive the store-side prune that follows.
    pub(crate) fn terminate_cvm(&self, id: &str) {
        self.reply_found(&cvm::cvm_action_path(id, "terminate"), operation_body(id));
    }

    /// `GET /api/v1/profiles/{id}`.
    pub(crate) fn get_profile(&self, id: &str, presence: Presence) {
        self.get_resource(profile::profile_path(id), presence, profile_body(id));
    }

    /// `GET /api/v1/me/keys` — the caller's registered keys (the Console has no
    /// per-key GET, so existence is a membership test on this list).
    pub(crate) fn list_keys(&self, ids: &[&str]) {
        self.reply_found(key::keys_path(), keys_body(ids));
    }

    /// `GET /api/v1/cvms?state=alive` — the caller's non-terminated CVMs, the
    /// live set `alias prune` reconciles cvm and session aliases against. Each id
    /// is returned `running`.
    pub(crate) fn list_alive_cvms(&self, ids: &[&str]) {
        let items = ids.iter().map(|id| cvm_body(id)).collect();
        self.reply_found(
            &format!("{}?state=alive", cvm::cvms_path()),
            list_page(items),
        );
    }

    /// `GET /api/v1/entities/{entity}/profiles` — the entity's profiles, the
    /// live set `alias prune` reconciles profile aliases against. Uses the fake
    /// session's [`FAKE_ENTITY_ID`].
    pub(crate) fn list_profiles(&self, ids: &[&str]) {
        let items = ids.iter().map(|id| profile_body(id)).collect();
        self.reply_found(&profile::profiles_path(FAKE_ENTITY_ID), list_page(items));
    }

    /// `DELETE /api/v1/me/keys/{id}` — a successful key removal (`204 No
    /// Content`), for the `key remove` auto-purge path.
    pub(crate) fn remove_key(&self, id: &str) {
        self.set(
            &key::key_path(id),
            Reply {
                status: 204,
                etag: None,
                body: String::new(),
            },
        );
    }

    /// Register a raw reply (arbitrary status + JSON body, no ETag) for `path`.
    /// For exercising the shared `console::send`/`post_json`/`fetch_json` status
    /// mapping directly, independent of any specific endpoint.
    pub(crate) fn reply_raw(&self, path: &str, status: u16, body: &str) {
        self.set(
            path,
            Reply {
                status,
                etag: None,
                body: body.to_string(),
            },
        );
    }

    // --- primitives (used by the endpoint helpers above) --------------------

    /// A GET-by-id resource endpoint: present (`200` + `body`) or absent (`404`).
    fn get_resource(&self, path: String, presence: Presence, body: Value) {
        match presence {
            Presence::Present => self.reply_found(&path, body),
            Presence::Absent => self.reply_not_found(&path),
        }
    }

    /// Reply `200 OK` with `body` (plus an ETag, which the etag-aware readers
    /// require) for `GET path`.
    fn reply_found(&self, path: &str, body: Value) {
        self.set(
            path,
            Reply {
                status: 200,
                etag: Some("\"mock-etag\"".to_string()),
                body: body.to_string(),
            },
        );
    }

    /// Reply `404 Not Found` with a Console error envelope for `GET path`.
    fn reply_not_found(&self, path: &str) {
        self.set(
            path,
            Reply {
                status: 404,
                etag: None,
                body: r#"{"error":{"code":"NOT_FOUND","message":"not found"}}"#.to_string(),
            },
        );
    }

    fn set(&self, path: &str, reply: Reply) {
        self.replies
            .lock()
            .expect("mock console lock")
            .insert(path.to_string(), reply);
    }
}

// Mock response bodies: fake JSON standing in for what the real Console would
// have generated, one per Console-backed alias kind (cvm / ssh-key / profile).
// `session` has none — a session is a local dtach session, not a Console
// resource, so there is nothing for the Console to serve.

/// Minimal `Cvm` JSON the CLI can parse (only the fields the reader requires;
/// optional fields default to null/None).
fn cvm_body(id: &str) -> Value {
    json!({
        "id": id,
        "owner": { "id": "user-1", "email": "user@example.com" },
        "entity_id": "entity-1",
        "profiles": [],
        "state": "running",
        "ssh_keys": [],
        "created_at": "2030-01-01T00:00:00Z",
        "updated_at": "2030-01-01T00:00:00Z"
    })
}

/// Minimal `Profile` JSON the CLI can parse.
fn profile_body(id: &str) -> Value {
    json!({
        "id": id,
        "entity_id": "entity-1",
        "name": "test",
        "description": "",
        "policy": {},
        "assigned": false,
        "attached_cvms": [],
        "attached_cvm_count": 0,
        "created_at": "2030-01-01T00:00:00Z",
        "updated_at": "2030-01-01T00:00:00Z"
    })
}

/// An already-`succeeded` `Operation` envelope for the async action endpoints
/// (`terminate`), carrying the terminated Cvm as its `result`. `wait_for_operation`
/// sees the terminal status and returns without polling, so this drives the whole
/// waited terminate (submit → wait → extract result) from one canned reply.
fn operation_body(cvm_id: &str) -> Value {
    json!({
        "id": "op-1",
        "kind": "cvm.terminate",
        "status": "succeeded",
        "actor_id": null,
        "target": { "type": "cvm", "id": cvm_id },
        "result": cvm_body(cvm_id),
        "error": null,
        "progress": null,
        "created_at": "2030-01-01T00:00:00Z",
        "updated_at": "2030-01-01T00:00:00Z",
        "expires_at": null
    })
}

/// Wrap `items` in a Console `ListPage` envelope (`items` + null `next_cursor`).
fn list_page(items: Vec<Value>) -> Value {
    json!({ "items": items, "next_cursor": null })
}

/// Minimal registered-SSH-key JSON the CLI can parse.
fn key_body(id: &str) -> Value {
    json!({
        "id": id,
        "label": "test",
        "fingerprint": "f",
        "public_key": "pk",
        "created_at": "2030-01-01T00:00:00Z"
    })
}

/// A `/me/keys` list page containing exactly `ids`.
fn keys_body(ids: &[&str]) -> Value {
    let items: Vec<Value> = ids.iter().map(|id| key_body(id)).collect();
    json!({ "items": items })
}

/// Read the request path, look up its canned reply, and write the HTTP response.
fn serve(mut stream: TcpStream, replies: &Mutex<HashMap<String, Reply>>) {
    let path = {
        let mut request_line = String::new();
        if BufReader::new(&stream)
            .read_line(&mut request_line)
            .is_err()
        {
            return;
        }
        // "GET /api/v1/... HTTP/1.1" -> the path in the middle.
        request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string()
    };
    let reply = replies
        .lock()
        .expect("mock console lock")
        .get(&path)
        .cloned();
    let response = match reply {
        Some(reply) => {
            let reason = match reply.status {
                200 => "OK",
                204 => "No Content",
                _ => "Not Found",
            };
            let mut head = format!("HTTP/1.1 {} {reason}\r\n", reply.status);
            if let Some(etag) = &reply.etag {
                head.push_str(&format!("ETag: {etag}\r\n"));
            }
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
            head.push_str("Connection: close\r\n\r\n");
            format!("{head}{}", reply.body)
        }
        None => {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        }
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}
