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

/// Trim a description to one line that fits a terminal, ellipsizing if needed.
fn summary(desc: &str) -> String {
    const MAX: usize = 70;
    let first = desc.split(". ").next().unwrap_or(desc).trim();
    if first.chars().count() > MAX {
        let cut: String = first.chars().take(MAX - 1).collect();
        format!("{}…", cut.trim_end())
    } else if first.len() < desc.len() {
        format!("{first}.")
    } else {
        first.to_string()
    }
}

fn find(name: &str) -> Option<&'static Skill> {
    SKILLS.iter().find(|s| s.name == name)
}

/// `vault skills list` — one line per skill: name + short description.
pub fn list() -> i32 {
    let width = SKILLS.iter().map(|s| s.name.len()).max().unwrap_or(0);
    for s in SKILLS {
        println!(
            "  {:<width$}  {}",
            s.name,
            summary(description(s.skill_md)),
            width = width
        );
    }
    0
}

/// `vault skills get <name> [--full]` — print SKILL.md, optionally with the
/// references and templates appended under `--- <rel> ---` delimiters.
pub fn get(names: &[String], full: bool) -> i32 {
    if names.is_empty() {
        eprintln!("error: skills get needs a skill name (try `vault skills list`)");
        return 1;
    }
    let mut first = true;
    for name in names {
        let Some(skill) = find(name) else {
            eprintln!("error: no skill named `{name}` (try `vault skills list`)");
            return 3;
        };
        if !first {
            println!();
        }
        first = false;
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
/// Honors `FNVAULT_SKILLS_DIR`; otherwise reports the build-time source
/// location. The skill is stored flat under the skills root, so a named
/// lookup resolves to that same directory.
pub fn path(name: Option<&str>) -> i32 {
    let raw = match std::env::var_os("FNVAULT_SKILLS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../skills")),
    };
    // Prefer a clean absolute path when the directory actually exists.
    let root = raw.canonicalize().unwrap_or(raw);
    if let Some(n) = name {
        if find(n).is_none() {
            eprintln!("error: no skill named `{n}` (try `vault skills list`)");
            return 3;
        }
    }
    println!("{}", root.display());
    0
}
