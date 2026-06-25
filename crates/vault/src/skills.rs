//! Bundled agent skills, embedded into the binary so they always match this
//! CLI version. Mirrors the `agent-browser skills` interface: `list`, `get`,
//! and `path`. The skill lives under `skills/` at the workspace root with a
//! `SKILL.md` plus optional `references/` and `templates/` files.

use std::path::PathBuf;

/// A reference or template file shipped alongside a skill's `SKILL.md`.
struct File {
    /// Path relative to the skill directory, e.g. `references/commands.md`.
    rel: &'static str,
    body: &'static str,
}

struct Skill {
    name: &'static str,
    /// Full `SKILL.md` contents, including YAML frontmatter.
    skill_md: &'static str,
    /// References and templates, emitted by `get --full` in order.
    extras: &'static [File],
}

macro_rules! embed {
    ($rel:literal) => {
        File {
            rel: $rel,
            body: include_str!(concat!("../../../skills/", $rel)),
        }
    };
}

/// The skill registry. Add a new skill by appending another entry.
const SKILLS: &[Skill] = &[Skill {
    name: "fnvault",
    skill_md: include_str!("../../../skills/SKILL.md"),
    extras: &[
        embed!("references/commands.md"),
        embed!("references/injection.md"),
        embed!("references/integrations.md"),
        embed!("references/security.md"),
        embed!("templates/inject-secrets.sh"),
        embed!("templates/rotate-check.sh"),
    ],
}];

/// Pull the `description:` value out of a SKILL.md frontmatter block.
fn description(skill_md: &str) -> &str {
    for line in skill_md.lines() {
        if let Some(rest) = line.strip_prefix("description:") {
            return rest.trim();
        }
        // Stop at the end of the frontmatter block.
        if line.trim() == "---" && !skill_md.starts_with(line) {
            break;
        }
    }
    ""
}

/// Word-wrap `text` to `width` columns (descriptions are ASCII).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn find(name: &str) -> Option<&'static Skill> {
    SKILLS.iter().find(|s| s.name == name)
}

/// `vault skills list [--json]` — list each skill with its full description.
pub fn list(json: bool) -> i32 {
    if json {
        let items: Vec<_> = SKILLS
            .iter()
            .map(|s| serde_json::json!({ "name": s.name, "description": description(s.skill_md) }))
            .collect();
        println!("{}", serde_json::json!({ "skills": items }));
        return 0;
    }

    if SKILLS.is_empty() {
        println!("(no skills bundled)");
        return 0;
    }

    println!("Available skills ({}):", SKILLS.len());
    for s in SKILLS {
        println!("\n  {}", s.name);
        for line in wrap(description(s.skill_md), 74) {
            println!("    {line}");
        }
    }
    println!("\nRun `vault skills get <name>` for the full guide.");
    0
}

/// `vault skills get <name> [--full] [--json]` — print SKILL.md, optionally
/// with references and templates (as `--- <rel> ---` sections, or a `files`
/// array under `--json`).
pub fn get(names: &[String], full: bool, json: bool) -> i32 {
    if names.is_empty() {
        eprintln!("error: skills get needs a skill name (try `vault skills list`)");
        return 1;
    }

    // Resolve every name first so a typo fails before any output.
    let mut skills = Vec::with_capacity(names.len());
    for name in names {
        let Some(skill) = find(name) else {
            eprintln!("error: no skill named `{name}` (try `vault skills list`)");
            return 3;
        };
        skills.push(skill);
    }

    if json {
        let items: Vec<_> = skills
            .iter()
            .map(|s| {
                let mut obj = serde_json::json!({
                    "name": s.name,
                    "description": description(s.skill_md),
                    "content": s.skill_md,
                });
                if full {
                    let files: Vec<_> = s
                        .extras
                        .iter()
                        .map(|f| serde_json::json!({ "path": f.rel, "content": f.body }))
                        .collect();
                    obj["files"] = serde_json::json!(files);
                }
                obj
            })
            .collect();
        println!("{}", serde_json::json!({ "skills": items }));
        return 0;
    }

    for (i, skill) in skills.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print!("{}", skill.skill_md);
        if full {
            for f in skill.extras {
                println!("\n--- {} ---\n", f.rel);
                print!("{}", f.body);
            }
        }
    }
    0
}

/// `vault skills path [name]` — print where the skill files live on disk.
/// Honors `FNVAULT_SKILLS_DIR`. Otherwise falls back to the build-time source
/// tree, which only exists in a checkout — a distributed binary (Homebrew,
/// release tarball, `cargo install`) has no on-disk skills dir, since the
/// content is embedded, so we say so instead of printing a stale build path.
pub fn path(name: Option<&str>) -> i32 {
    if let Some(n) = name {
        if find(n).is_none() {
            eprintln!("error: no skill named `{n}` (try `vault skills list`)");
            return 3;
        }
    }

    // An explicit override always wins; print it canonicalized if it exists.
    if let Some(dir) = std::env::var_os("FNVAULT_SKILLS_DIR") {
        let p = PathBuf::from(dir);
        println!("{}", p.canonicalize().unwrap_or(p).display());
        return 0;
    }

    // Build-time source location — present only when run from a checkout.
    let build = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../skills"));
    if let Ok(real) = build.canonicalize() {
        println!("{}", real.display());
        return 0;
    }

    eprintln!("skills are embedded in this binary; there is no on-disk path.");
    eprintln!("set FNVAULT_SKILLS_DIR to point `vault skills path` at a directory.");
    0
}
