//! Synchronous client to the daemon. Auto-spawns `vaultd` when the socket is
//! not yet up.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

use vaultcore::paths;
use vaultcore::protocol::{Request, Response};

/// Send one request and read one response, spawning the daemon if needed.
pub fn request(req: &Request) -> Result<Response> {
    let mut stream = connect()?;
    stream
        .write_all(req.encode().as_bytes())
        .context("write request")?;
    stream.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).context("read response")?;
    if n == 0 {
        return Err(anyhow!("daemon closed the connection"));
    }
    serde_json::from_str::<Response>(line.trim()).context("parse response")
}

fn connect() -> Result<UnixStream> {
    let path = paths::socket_path();
    if let Ok(s) = UnixStream::connect(&path) {
        return Ok(s);
    }
    spawn_daemon().context("spawn vaultd")?;
    wait_for_socket(&path, Duration::from_secs(5))
}

fn daemon_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("current_exe")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot locate binary directory"))?;
    let candidate = dir.join("vaultd");
    if candidate.exists() {
        Ok(candidate)
    } else {
        // Fall back to PATH.
        Ok(PathBuf::from("vaultd"))
    }
}

fn spawn_daemon() -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let mut cmd = Command::new(daemon_path()?);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Detach into a new session so the daemon outlives the spawning shell and
    // does not receive its SIGINT/SIGHUP.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().context("failed to start vaultd")?;
    Ok(())
}

fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> Result<UnixStream> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = UnixStream::connect(path) {
            return Ok(s);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for vaultd to start"));
        }
        sleep(Duration::from_millis(50));
    }
}
