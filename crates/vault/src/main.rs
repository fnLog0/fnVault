//! fnVault CLI client and TUI launcher.

mod client;
mod skills;
mod tui;

use std::io::{Read, Write};

use clap::{Args, CommandFactory, Parser, Subcommand};

use vaultcore::protocol::{Request, Response};
use vaultcore::store::SecretRecord;
use vaultcore::{backup, paths, totp};

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
        /// Expiry date for rotation reminders, e.g. 2026-12-31.
        #[arg(long)]
        expires: Option<String>,
    },
    /// Print a secret to stdout (unlocks with Touch ID if needed).
    Get {
        name: String,
        /// Append a trailing newline.
        #[arg(long, short)]
        newline: bool,
    },
    /// Print the current TOTP/2FA code for a stored base32 seed.
    Otp { name: String },
    /// Run a command with secrets injected as environment variables.
    ///
    /// Example: vault run -e GH_TOKEN=github-token -- gh repo list
    Run {
        /// VAR=secret-name (repeatable).
        #[arg(short = 'e', long = "env", value_name = "VAR=secret")]
        env: Vec<String>,
        /// The command to run, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// List secret names and tags (no unlock required).
    List,
    /// Delete a secret.
    Rm { name: String },
    /// Export the whole vault to a passphrase-encrypted file.
    Export { file: String },
    /// Import secrets from a file created by `vault export`.
    Import { file: String },
    /// Show recent access events from the daemon log.
    Audit {
        #[arg(short = 'n', long = "lines", default_value_t = 20)]
        lines: usize,
    },
    /// Relock the vault now.
    Lock,
    /// Trigger Touch ID without reading a secret.
    Unlock,
    /// Show session state and idle countdown.
    Status,
    /// Print shell completions (bash|zsh|fish|powershell|elvish).
    Completions { shell: clap_complete::Shell },
    /// Show bundled agent skills (list | get | path).
    Skills(SkillsArgs),
    /// Launch the interactive TUI dashboard (default with no command).
    Ui,
}

#[derive(Args)]
struct SkillsArgs {
    #[command(subcommand)]
    command: Option<SkillsCommand>,
}

#[derive(Subcommand)]
enum SkillsCommand {
    /// List available skills (default).
    List {
        /// Emit the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a skill's SKILL.md; --full appends references and templates.
    Get {
        #[arg(required = true)]
        names: Vec<String>,
        /// Include the skill's reference and template files.
        #[arg(long)]
        full: bool,
        /// Emit the skill(s) as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the filesystem path to the skills directory (or one skill).
    Path { name: Option<String> },
}

fn main() {
    // Restore default SIGPIPE handling so piping output into `head`/`grep` (which
    // close the pipe early) exits quietly instead of panicking on a broken pipe.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

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
        Command::Otp { name } => cmd_otp(name),
        Command::Run { env, cmd } => cmd_run(env, cmd),
        Command::Set {
            name,
            tag,
            stdin,
            expires,
        } => cmd_set(name, tag, stdin, expires),
        Command::Export { file } => cmd_export(file),
        Command::Import { file } => cmd_import(file),
        Command::Audit { lines } => cmd_audit(lines),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "vault", &mut std::io::stdout());
            0
        }
        Command::Skills(args) => {
            match args.command.unwrap_or(SkillsCommand::List { json: false }) {
                SkillsCommand::List { json } => skills::list(json),
                SkillsCommand::Get { names, full, json } => skills::get(&names, full, json),
                SkillsCommand::Path { name } => skills::path(name.as_deref()),
            }
        }
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
            println!(
                "state       : {}",
                if s.unlocked { "unlocked" } else { "locked" }
            );
            println!("idle timeout: {}s", s.idle_timeout_secs);
            if let Some(since) = s.since_activity_secs {
                println!("idle for    : {since}s");
            }
            match s.idle_remaining_secs {
                Some(r) => println!("relock in   : {} (idle)", fmt_secs(r)),
                None if s.unlocked => println!("relock in   : never (idle timeout disabled)"),
                None => {}
            }
            if let Some(r) = s.session_remaining_secs {
                println!("session cap : {} left", fmt_secs(r));
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
                    let mut extra = String::new();
                    if !s.tag.is_empty() {
                        extra.push_str(&format!("  [{}]", s.tag));
                    }
                    if let Some(exp) = &s.expires {
                        extra.push_str(&format!("  expires {exp}"));
                    }
                    println!("{:<width$}{}", s.name, extra, width = width);
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

fn cmd_otp(name: String) -> i32 {
    match talk(Request::Get { name }) {
        Response::Secret { value } => match totp::totp_now(value.trim()) {
            Ok(code) => {
                println!("{code}  (valid {}s)", totp::seconds_remaining());
                0
            }
            Err(e) => fail("crypto", &e.to_string()),
        },
        Response::Error { code, message } => fail(&code, &message),
        other => fail("protocol", &format!("unexpected response: {other:?}")),
    }
}

fn cmd_run(env: Vec<String>, cmd: Vec<String>) -> i32 {
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for entry in &env {
        let Some((var, name)) = entry.split_once('=') else {
            return fail("protocol", &format!("bad --env (want VAR=secret): {entry}"));
        };
        match talk(Request::Get {
            name: name.to_string(),
        }) {
            Response::Secret { value } => {
                command.env(var, value);
            }
            Response::Error { code, message } => return fail(&code, &message),
            other => return fail("protocol", &format!("unexpected response: {other:?}")),
        }
    }
    match command.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => fail("io", &format!("running {}: {e}", cmd[0])),
    }
}

fn cmd_set(name: String, tag: String, use_stdin: bool, expires: Option<String>) -> i32 {
    let value = if use_stdin {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            return fail("io", &format!("reading stdin: {e}"));
        }
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

    simple(
        Request::Set {
            name,
            tag,
            value,
            expires,
        },
        "secret stored",
    )
}

fn cmd_export(file: String) -> i32 {
    let records = match talk(Request::ExportAll) {
        Response::Export { records } => records,
        Response::Error { code, message } => return fail(&code, &message),
        other => return fail("protocol", &format!("unexpected response: {other:?}")),
    };
    let pass = match prompt_new_passphrase() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let json = match serde_json::to_vec(&records) {
        Ok(j) => j,
        Err(e) => return fail("protocol", &format!("serialize: {e}")),
    };
    let blob = match backup::seal(&pass, &json) {
        Ok(b) => b,
        Err(e) => return fail("crypto", &e.to_string()),
    };
    if let Err(e) = write_private(&file, &blob) {
        return fail("io", &format!("writing {file}: {e}"));
    }
    println!("exported {} secrets to {file}", records.len());
    0
}

fn cmd_import(file: String) -> i32 {
    let blob = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => return fail("io", &format!("reading {file}: {e}")),
    };
    let pass = match rpassword::prompt_password("Passphrase: ") {
        Ok(p) => p,
        Err(e) => return fail("io", &format!("reading passphrase: {e}")),
    };
    let json = match backup::open(&pass, &blob) {
        Ok(j) => j,
        Err(e) => return fail("crypto", &format!("{e} (wrong passphrase?)")),
    };
    let records: Vec<SecretRecord> = match serde_json::from_slice(&json) {
        Ok(r) => r,
        Err(e) => return fail("protocol", &format!("parse: {e}")),
    };
    let mut imported = 0;
    for r in &records {
        match talk(Request::Set {
            name: r.name.clone(),
            tag: r.tag.clone(),
            value: r.value.clone(),
            expires: r.expires.clone(),
        }) {
            Response::Ok => imported += 1,
            Response::Error { code, message } => return fail(&code, &message),
            other => return fail("protocol", &format!("unexpected response: {other:?}")),
        }
    }
    println!("imported {imported} secrets from {file}");
    0
}

fn cmd_audit(lines: usize) -> i32 {
    let path = paths::log_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            println!("(no log yet at {})", path.display());
            return 0;
        }
    };
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    for line in &all[start..] {
        println!("{line}");
    }
    0
}

fn prompt_new_passphrase() -> Result<String, i32> {
    let p1 = rpassword::prompt_password("New passphrase: ")
        .map_err(|e| fail("io", &format!("reading passphrase: {e}")))?;
    if p1.is_empty() {
        return Err(fail("protocol", "passphrase must not be empty"));
    }
    let p2 = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|e| fail("io", &format!("reading passphrase: {e}")))?;
    if p1 != p2 {
        return Err(fail("protocol", "passphrases do not match"));
    }
    Ok(p1)
}

fn write_private(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
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
