//! fnVault daemon: holds the unlocked master key for the session, enforces the
//! idle-timeout backstop, and serves requests over a per-user Unix socket.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use vaultcore::error::{Result as VResult, VaultError};
use vaultcore::keychain;
use vaultcore::paths;
use vaultcore::protocol::{Request, Response, StatusInfo};
use vaultcore::session::Session;
use vaultcore::store;

type Shared = Arc<Mutex<Session>>;

const DEFAULT_IDLE_SECS: u64 = 900; // 15 minutes
const IDLE_CHECK_SECS: u64 = 15;
const UNLOCK_REASON: &str = "Unlock fnVault to access your credentials";

#[tokio::main]
async fn main() -> Result<()> {
    let runtime_dir = paths::runtime_dir();
    fs::create_dir_all(&runtime_dir).context("create runtime dir")?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).ok();

    init_logging();

    let idle_secs = std::env::var("FNVAULT_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_IDLE_SECS);
    let idle_timeout = Duration::from_secs(idle_secs);

    let sock = paths::socket_path();
    // Refuse to start a second daemon; clean up a stale socket otherwise.
    if sock.exists() {
        if UnixStream::connect(&sock).await.is_ok() {
            tracing::info!("daemon already running, exiting");
            return Ok(());
        }
        let _ = fs::remove_file(&sock);
    }

    let listener = UnixListener::bind(&sock).context("bind unix socket")?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).context("chmod socket")?;
    tracing::info!(?sock, idle_secs, "vaultd started");

    let session: Shared = Arc::new(Mutex::new(Session::new(idle_timeout)));

    // Idle-timeout backstop.
    {
        let session = session.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(IDLE_CHECK_SECS));
            loop {
                tick.tick().await;
                if session.lock().await.maybe_relock() {
                    tracing::info!("idle timeout reached: vault relocked");
                }
            }
        });
    }

    let our_uid = unsafe { libc::getuid() };

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!(error=%e, "accept failed"); continue; }
                };
                match peer_uid(&stream) {
                    Some(uid) if uid == our_uid => {
                        let session = session.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, session).await {
                                tracing::warn!(error=%e, "connection ended with error");
                            }
                        });
                    }
                    other => {
                        tracing::warn!(?other, "rejecting connection from non-owner uid");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal: locking and exiting");
                session.lock().await.lock();
                let _ = fs::remove_file(&sock);
                // Force exit even if a Touch ID prompt is still blocking a
                // worker thread.
                std::process::exit(0);
            }
        }
    }
}

fn init_logging() {
    let writer = tracing_appender::rolling::never(paths::runtime_dir(), "vaultd.log");
    let filter = std::env::var("FNVAULT_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let r = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if r == 0 {
        Some(uid)
    } else {
        None
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

async fn handle_conn(stream: UnixStream, session: Shared) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(req, &session).await,
            Err(e) => Response::Error {
                code: "protocol".into(),
                message: format!("bad request: {e}"),
            },
        };
        writer.write_all(response.encode().as_bytes()).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn dispatch(req: Request, session: &Shared) -> Response {
    match dispatch_inner(req, session).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!(code = e.code(), "request error");
            Response::error(&e)
        }
    }
}

async fn dispatch_inner(req: Request, session: &Shared) -> VResult<Response> {
    match req {
        Request::Ping => Ok(Response::Ok),
        Request::Init => {
            store::init()?;
            tracing::info!("vault initialized");
            Ok(Response::Ok)
        }
        Request::Status => Ok(Response::Status(build_status(session).await)),
        Request::List => Ok(Response::List {
            secrets: store::list()?,
        }),
        Request::Lock => {
            session.lock().await.lock();
            tracing::info!("vault locked (manual)");
            Ok(Response::Ok)
        }
        Request::Unlock => {
            require_init()?;
            ensure_unlocked(session).await?;
            Ok(Response::Ok)
        }
        Request::Get { name } => {
            require_init()?;
            ensure_unlocked(session).await?;
            let key = current_key(session).await?;
            let value = store::get_secret(&key, &name)?;
            Ok(Response::Secret {
                value: to_utf8(value)?,
            })
        }
        Request::Set { name, tag, value } => {
            require_init()?;
            ensure_unlocked(session).await?;
            let key = current_key(session).await?;
            store::set_secret(&key, &name, &tag, value.as_bytes())?;
            tracing::info!(secret = %name, "secret stored");
            Ok(Response::Ok)
        }
        Request::Delete { name } => {
            require_init()?;
            ensure_unlocked(session).await?;
            store::delete_secret(&name)?;
            tracing::info!(secret = %name, "secret deleted");
            Ok(Response::Ok)
        }
    }
}

fn require_init() -> VResult<()> {
    if store::is_initialized() {
        Ok(())
    } else {
        Err(VaultError::NotInitialized)
    }
}

fn to_utf8(bytes: Vec<u8>) -> VResult<String> {
    String::from_utf8(bytes).map_err(|_| VaultError::Protocol("secret is not valid UTF-8".into()))
}

/// Ensure the session holds the master key, prompting Touch ID if needed.
async fn ensure_unlocked(session: &Shared) -> VResult<()> {
    if session.lock().await.is_unlocked() {
        session.lock().await.touch();
        return Ok(());
    }
    // Touch ID blocks on the user, so run it off the async runtime.
    let key = tokio::task::spawn_blocking(|| keychain::touch_id_unlock(UNLOCK_REASON))
        .await
        .map_err(|e| VaultError::Protocol(format!("unlock task panicked: {e}")))??;
    session.lock().await.set_key(key);
    tracing::info!("vault unlocked");
    Ok(())
}

async fn current_key(session: &Shared) -> VResult<Zeroizing<[u8; vaultcore::crypto::KEY_LEN]>> {
    let mut s = session.lock().await;
    Ok(Zeroizing::new(*s.key()?))
}

async fn build_status(session: &Shared) -> StatusInfo {
    let s = session.lock().await;
    StatusInfo {
        initialized: store::is_initialized(),
        unlocked: s.is_unlocked(),
        idle_timeout_secs: s.idle_timeout().as_secs(),
        since_activity_secs: if s.is_unlocked() {
            Some(s.since_activity().as_secs())
        } else {
            None
        },
        idle_remaining_secs: s.idle_remaining().map(|d| d.as_secs()),
    }
}
