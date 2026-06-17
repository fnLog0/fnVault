//! fnVault CLI client and TUI launcher.

mod client;
mod tui;

use std::io::{Read, Write};

use clap::{Parser, Subcommand};

use vaultcore::protocol::{Request, Response};

#[derive(Parser)]
#[command(
    name = "vault",
    about = "fnVault — a Touch ID-gated credential vault",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the master key and enroll Touch ID.
    Init,
    /// Add or update a secret (value via --stdin or a hidden prompt).
    Set {
        name: String,
        #[arg(long, default_value = "")]
        tag: String,
        /// Read the value from stdin instead of prompting.
        #[arg(long)]
        stdin: bool,
    },
    /// Print a secret to stdout (unlocks with Touch ID if needed).
    Get {
        name: String,
        /// Append a trailing newline.
        #[arg(long, short)]
        newline: bool,
    },
    /// List secret names and tags (no unlock required).
    List,
    /// Delete a secret.
    Rm { name: String },
    /// Relock the vault now.
    Lock,
    /// Trigger Touch ID without reading a secret.
    Unlock,
    /// Show session state and idle countdown.
    Status,
    /// Launch the interactive TUI dashboard (default with no command).
    Ui,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        None | Some(Command::Ui) => match tui::run() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e:#}");
                1
            }
        },
        Some(cmd) => run_command(cmd),
    };
    std::process::exit(code);
}

fn run_command(cmd: Command) -> i32 {
    match cmd {
        Command::Init => simple(Request::Init, "vault initialized"),
        Command::Lock => simple(Request::Lock, "vault locked"),
        Command::Unlock => simple(Request::Unlock, "vault unlocked"),
        Command::Rm { name } => simple(Request::Delete { name }, "secret deleted"),
        Command::Status => cmd_status(),
        Command::List => cmd_list(),
        Command::Get { name, newline } => cmd_get(name, newline),
        Command::Set { name, tag, stdin } => cmd_set(name, tag, stdin),
        Command::Ui => 0, // handled in main()
    }
}

/// Send a request, returning a Response even when the daemon is unreachable.
fn talk(req: Request) -> Response {
    match client::request(&req) {
        Ok(resp) => resp,
        Err(e) => Response::Error {
            code: "daemon_unreachable".into(),
            message: e.to_string(),
        },
    }
}

fn simple(req: Request, ok_msg: &str) -> i32 {
    match talk(req) {
        Response::Ok => {
            println!("{ok_msg}");
            0
        }
        Response::Error { code, message } => fail(&code, &message),
        other => fail("protocol", &format!("unexpected response: {other:?}")),
    }
}

fn cmd_status() -> i32 {
    match talk(Request::Status) {
        Response::Status(s) => {
            println!("initialized : {}", s.initialized);
            println!("state       : {}", if s.unlocked { "unlocked" } else { "locked" });
            println!("idle timeout: {}s", s.idle_timeout_secs);
            if let Some(since) = s.since_activity_secs {
                println!("idle for    : {since}s");
            }
            match s.idle_remaining_secs {
                Some(r) => println!("relock in   : {}", fmt_secs(r)),
                None if s.unlocked => println!("relock in   : never (idle timeout disabled)"),
                None => {}
            }
            0
        }
        Response::Error { code, message } => fail(&code, &message),
        other => fail("protocol", &format!("unexpected response: {other:?}")),
    }
}

fn cmd_list() -> i32 {
    match talk(Request::List) {
        Response::List { secrets } => {
            if secrets.is_empty() {
                println!("(no secrets yet — add one with `vault set <name>`)");
            } else {
                let width = secrets.iter().map(|s| s.name.len()).max().unwrap_or(0);
                for s in secrets {
                    let tag = if s.tag.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", s.tag)
                    };
                    println!("{:<width$}{}", s.name, tag, width = width);
                }
            }
            0
        }
        Response::Error { code, message } => fail(&code, &message),
        other => fail("protocol", &format!("unexpected response: {other:?}")),
    }
}

fn cmd_get(name: String, newline: bool) -> i32 {
    match talk(Request::Get { name }) {
        Response::Secret { value } => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let _ = out.write_all(value.as_bytes());
            if newline {
                let _ = out.write_all(b"\n");
            }
            let _ = out.flush();
            0
        }
        Response::Error { code, message } => fail(&code, &message),
        other => fail("protocol", &format!("unexpected response: {other:?}")),
    }
}

fn cmd_set(name: String, tag: String, use_stdin: bool) -> i32 {
    let value = if use_stdin {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            return fail("io", &format!("reading stdin: {e}"));
        }
        // Strip a single trailing newline from piped input.
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    } else {
        match rpassword::prompt_password(format!("Value for `{name}`: ")) {
            Ok(v) => v,
            Err(e) => return fail("io", &format!("reading value: {e}")),
        }
    };

    simple(Request::Set { name, tag, value }, "secret stored")
}

fn fail(code: &str, message: &str) -> i32 {
    eprintln!("error: {message}");
    match code {
        "locked" | "auth_failed" => 2,
        "not_found" => 3,
        "daemon_unreachable" => 4,
        _ => 1,
    }
}

fn fmt_secs(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}
