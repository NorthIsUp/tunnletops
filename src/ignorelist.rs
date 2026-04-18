use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// Matches the phi.yaml semantic model:
/// - `type: "file"` entries skip the entire file (whole-file ignore).
/// - `scope: "line"` matches on (path, line_num, entity_type, text).
/// - `scope: "file"` matches on (path, entity_type, text).
/// - `scope: "global"` matches on (entity_type, text).
/// - Missing `text` is treated as "any text" (so you can ignore
///   all findings of a given type in a file).
///
/// `path` supports shell-style glob syntax: `*`, `?`, `[...]`, and `**`
/// for recursive directory match. Examples:
/// ```toml
/// path = "docs/generated/**"     # recursive under docs/generated
/// path = "src/**/*_test.py"      # any test file under src
/// path = "vendor/bundle.js"      # exact match (no glob chars)
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreEntry {
    // Field order here is the TOML serialization order. We put the "what
    // kind of entry is this?" fields first (type for whole-file skips;
    // entity_type for regular), then narrowing scope/path/line, then the
    // matchers (text / glob / match). Makes each [[ignored]] block's first
    // visible line tell you what it's about.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// File path or glob pattern. `file` is accepted as an alias for
    /// backward compatibility with ignorelists written before 0.5.21;
    /// `save()` always writes `path`. Supports `*`, `?`, `[...]`, and
    /// `**` for recursive directory match.
    #[serde(
        default,
        alias = "file",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<String>,
    /// Lines this rule applies to (line scope). Accepts a single number,
    /// a comma list, or inclusive `start..end` ranges. Examples:
    /// `line = "5"`, `line = "1,5,8..29"`. Range bounds are inclusive
    /// on both ends — `8..29` matches lines 8 through 29.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    /// Text matcher (case-insensitive). Auto-detects shape:
    ///
    /// - Contains glob metachars (`*`, `?`, `[`) → anchored glob over the
    ///   finding's full text. `**` matches across segments.
    /// - No metachars → literal exact compare.
    ///
    /// Per-entity wildcards layer on top of literal compare:
    /// - EMAIL_ADDRESS: leading `@` matches by domain, trailing `@` by
    ///   username (e.g. `text = "@askclara.com"`).
    /// - URL: `text = "*.host"` is host-aware (apex + every subdomain),
    ///   not a generic full-text glob — so `*.metriport.com` matches
    ///   `https://api.metriport.com/foo` even though the URL doesn't
    ///   end in `.metriport.com`.
    ///
    /// Mutually exclusive with `match` on a single entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Opt out of glob auto-detection on `text`. Default (unset / true)
    /// promotes a `text` containing `*`/`?`/`[` to an anchored glob; set
    /// to `false` to keep `text` strictly literal even when it looks
    /// glob-y. Useful for matching paths or expressions that genuinely
    /// contain `*` (e.g. `text = "C:\\Users\\*\\AppData"` literal). The
    /// per-entity wildcards (email `@host`, URL `*.host`) still apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub textglob: Option<bool>,
    /// Regex over the finding's full text. `pattern` is accepted as a
    /// silent alias for backward compatibility; `save()` writes `match`.
    /// Use TOML literal strings (single quotes) to avoid double-escaping
    /// backslashes:
    ///
    /// ```toml
    /// match = '@\w+\.askclara\.com'
    /// ```
    ///
    /// Mutually exclusive with `text` and `glob`.
    #[serde(
        default,
        rename = "match",
        alias = "pattern",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnorelistFile {
    /// Per-project enable/disable of entity types. Declared first so it
    /// serializes above `[[ignored]]` blocks — TOML serializes struct
    /// fields in declaration order and top-level tables conventionally
    /// come before array-of-tables.
    #[serde(default, skip_serializing_if = "entities_is_empty")]
    pub entities: EntitiesConfig,
    #[serde(default)]
    pub ignored: Vec<IgnoreEntry>,
}

fn entities_is_empty(e: &EntitiesConfig) -> bool {
    e.flags.is_empty()
}

/// `[entities]` section — a flat `NAME = true|false` map. Entity types
/// default to enabled; set to `false` to skip them entirely. Example:
///
/// ```toml
/// [entities]
/// URL = false
/// MAC_ADDRESS = false
/// ```
///
/// Case-sensitive — match the emitted `entity_type` exactly.
/// `BTreeMap` so save-out is deterministically alphabetical.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntitiesConfig {
    pub flags: std::collections::BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Default)]
struct CompiledMatchers {
    /// Compiled regex for the `match` (a.k.a. `pattern`) field.
    regex: Option<Regex>,
    /// Compiled glob for the `path` field (file/directory match). None when
    /// `path` is a literal — a literal string compare is cheaper.
    path: Option<glob::Pattern>,
    /// Compiled glob for the `text` field when it contains glob metachars.
    /// None means we'll fall through to literal/case-insensitive compare
    /// plus per-entity wildcards (email `@host`, URL `*.host`).
    text: Option<glob::Pattern>,
    /// Parsed line range spec (for `line = "1,5,8..29"`-style values).
    /// None when `line` is unset; `Some(spec)` even for single-line entries.
    line: Option<LineSpec>,
}

#[derive(Debug, Clone, Default)]
pub struct Ignorelist {
    entries: Vec<IgnoreEntry>,
    /// Parallel to `entries`: compiled matchers for each entry.
    compiled: Vec<CompiledMatchers>,
    /// Fast-path for whole-file skips: exact literal paths.
    whole_file_skips_literal: HashSet<String>,
    /// Whole-file skip globs. Checked after `whole_file_skips_literal`.
    whole_file_skips_glob: Vec<glob::Pattern>,
    disabled_entities: HashSet<String>,
}

/// One or more inclusive line ranges. `LineSpec::parse("1,5,8..29")` yields
/// the set `{1, 5, 8..=29}`. Single-number entries are stored as `(n, n)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineSpec {
    /// Inclusive (start, end) intervals. Order is preserved from the input
    /// string; we don't normalize / merge / sort because the typical entry
    /// has 1-3 ranges and `contains` is linear either way.
    intervals: Vec<(u32, u32)>,
}

impl LineSpec {
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let mut intervals = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((a, b)) = part.split_once("..") {
                let a: u32 = a.trim().parse().map_err(|_| {
                    format!("invalid line range start `{}` in `{}`", a.trim(), s)
                })?;
                let b: u32 = b.trim().parse().map_err(|_| {
                    format!("invalid line range end `{}` in `{}`", b.trim(), s)
                })?;
                if a > b {
                    return Err(format!("line range start > end in `{}`", part));
                }
                intervals.push((a, b));
            } else {
                let n: u32 = part
                    .parse()
                    .map_err(|_| format!("invalid line number `{}` in `{}`", part, s))?;
                intervals.push((n, n));
            }
        }
        if intervals.is_empty() {
            return Err(format!("empty line spec `{}`", s));
        }
        Ok(Self { intervals })
    }

    pub fn contains(&self, n: u32) -> bool {
        self.intervals.iter().any(|&(a, b)| a <= n && n <= b)
    }
}

/// Effective scope for an entry, derived from what fields are set.
/// Inference rules (evaluated in order):
/// 1. `line` present → line
/// 2. `path` present → file
/// 3. neither       → global
///
/// An explicit `scope = "…"` on the entry overrides the inference; on save
/// we strip the field when it matches what inference would have picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    File,
    Line,
}

fn infer_scope(e: &IgnoreEntry) -> Scope {
    if e.line.is_some() {
        Scope::Line
    } else if e.path.is_some() {
        Scope::File
    } else {
        Scope::Global
    }
}

fn effective_scope(e: &IgnoreEntry) -> Scope {
    match e.scope.as_deref() {
        Some("line") => Scope::Line,
        Some("file") => Scope::File,
        Some("global") => Scope::Global,
        _ => infer_scope(e),
    }
}

/// Compile `s` as a glob iff it contains glob metachars; otherwise None
/// (we'll fall back to literal string compare, which is cheaper). Used for
/// both `path` and `text` fields — same metachar semantics in both places.
fn compile_glob(s: &str) -> Option<glob::Pattern> {
    if s.chars().any(|c| matches!(c, '*' | '?' | '[')) {
        glob::Pattern::new(s).ok()
    } else {
        None
    }
}

fn path_matches(entry_path: &str, compiled: Option<&glob::Pattern>, target: &str) -> bool {
    match compiled {
        Some(g) => g.matches(target),
        None => entry_path == target,
    }
}

/// Reject entries that set more than one of `text` / `match` — they're
/// alternative matchers, never both. Returns the offending field name pair
/// in the error so the user can find which `[[ignored]]` block to fix.
fn validate_entry(entry: &IgnoreEntry) -> Result<()> {
    if entry.text.is_some() && entry.regex.is_some() {
        anyhow::bail!(
            "ignore entry sets both `text` and `match` (or `pattern`) — pick one"
        );
    }
    Ok(())
}

impl Ignorelist {
    pub fn load_or_empty(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        // Legacy YAML fallback: if the file extension is .yaml/.yml, reuse the
        // phi.yaml parser from the migrate module so users don't have to
        // convert before they can scan. The [entities] section isn't
        // expressible in legacy phi.yaml, but ignore rules come through.
        let file: IgnorelistFile = match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => crate::migrate::load_legacy_yaml(&text)
                .with_context(|| format!("parsing legacy YAML {}", path.display()))?,
            _ => toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?,
        };
        let mut out = Self::default();
        for e in file.ignored {
            validate_entry(&e)
                .with_context(|| format!("invalid ignore entry in {}", path.display()))?;
            let path_glob = e.path.as_deref().and_then(compile_glob);
            if e.kind.as_deref() == Some("file") {
                if let Some(p) = &e.path {
                    match &path_glob {
                        Some(g) => out.whole_file_skips_glob.push(g.clone()),
                        None => {
                            out.whole_file_skips_literal.insert(p.clone());
                        }
                    }
                }
            }
            let regex = e.regex.as_ref().and_then(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(err) => {
                    eprintln!(
                        "warning: invalid `match` regex in {}: {} (skipping this ignore rule)",
                        path.display(),
                        err
                    );
                    None
                }
            });
            let text_glob = if e.textglob == Some(false) {
                None
            } else {
                e.text.as_deref().and_then(compile_glob)
            };
            let line_spec = match e.line.as_deref() {
                Some(s) => Some(LineSpec::parse(s).map_err(|m| {
                    anyhow::anyhow!("invalid `line` in {}: {}", path.display(), m)
                })?),
                None => None,
            };
            out.entries.push(e);
            out.compiled.push(CompiledMatchers {
                regex,
                path: path_glob,
                text: text_glob,
                line: line_spec,
            });
        }
        out.disabled_entities = file
            .entities
            .flags
            .into_iter()
            .filter_map(|(k, enabled)| if !enabled { Some(k) } else { None })
            .collect();
        Ok(out)
    }

    pub fn is_entity_disabled(&self, entity_type: &str) -> bool {
        self.disabled_entities.contains(entity_type)
    }

    pub fn is_file_skipped(&self, file: &str) -> bool {
        if self.whole_file_skips_literal.contains(file) {
            return true;
        }
        self.whole_file_skips_glob.iter().any(|g| g.matches(file))
    }

    pub fn is_ignored(&self, f: &Finding) -> bool {
        for (entry, c) in self.entries.iter().zip(self.compiled.iter()) {
            if entry.kind.as_deref() == Some("file") {
                // Handled via `is_file_skipped`; don't double-match.
                continue;
            }
            if let Some(et) = &entry.entity_type {
                if et != &f.entity_type {
                    continue;
                }
            }
            if !matches_criteria(entry, c, f) {
                continue;
            }
            let file_ok = || match entry.path.as_deref() {
                Some(p) => path_matches(p, c.path.as_ref(), &f.file),
                None => false,
            };
            match effective_scope(entry) {
                Scope::Line => {
                    if file_ok()
                        && c.line.as_ref().map(|s| s.contains(f.line_num)).unwrap_or(false)
                    {
                        return true;
                    }
                }
                Scope::File => {
                    if file_ok() {
                        return true;
                    }
                }
                Scope::Global => return true,
            }
        }
        false
    }

    pub fn append(&mut self, entry: IgnoreEntry) {
        let path_glob = entry.path.as_deref().and_then(compile_glob);
        if entry.kind.as_deref() == Some("file") {
            if let Some(p) = &entry.path {
                match &path_glob {
                    Some(g) => self.whole_file_skips_glob.push(g.clone()),
                    None => {
                        self.whole_file_skips_literal.insert(p.clone());
                    }
                }
            }
        }
        let regex = entry.regex.as_ref().and_then(|p| Regex::new(p).ok());
        let text_glob = if entry.textglob == Some(false) {
            None
        } else {
            entry.text.as_deref().and_then(compile_glob)
        };
        let line_spec = entry.line.as_deref().and_then(|s| LineSpec::parse(s).ok());
        self.entries.push(entry);
        self.compiled.push(CompiledMatchers {
            regex,
            path: path_glob,
            text: text_glob,
            line: line_spec,
        });
    }

    #[allow(dead_code)]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut ignored = self.entries.clone();
        // Drop redundant explicit `scope` — inference will recover it on load.
        // Keeps saved files minimal (one less field per entry).
        for e in ignored.iter_mut() {
            if e.scope.is_some() {
                let explicit = effective_scope(e);
                e.scope = None;
                if infer_scope(e) != explicit {
                    // Inference would disagree; restore the explicit field.
                    e.scope = Some(
                        match explicit {
                            Scope::Line => "line",
                            Scope::File => "file",
                            Scope::Global => "global",
                        }
                        .to_string(),
                    );
                }
            }
        }
        ignored.sort_by_key(sort_key);
        let file = IgnorelistFile {
            ignored,
            entities: EntitiesConfig {
                flags: self
                    .disabled_entities
                    .iter()
                    .map(|k| (k.clone(), false))
                    .collect(),
            },
        };
        let text = toml::to_string_pretty(&file).context("serializing ignorelist")?;
        let text = insert_group_breaks(&text);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

/// Insert an extra blank line between consecutive `[[ignored]]` blocks
/// whose `entity_type` or `type` header field changes. Makes groupings
/// visible without restructuring the file.
fn insert_group_breaks(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    let mut prev_header: Option<String> = None;
    for block in text.split_inclusive("\n\n") {
        let trimmed = block.trim_start();
        let header = if trimmed.starts_with("[[ignored]]") {
            // Identify the group: first of entity_type / type value.
            extract_header_field(trimmed, "entity_type")
                .or_else(|| extract_header_field(trimmed, "type"))
        } else {
            None
        };
        if let (Some(prev), Some(cur)) = (&prev_header, &header) {
            if prev != cur {
                out.push('\n');
            }
        }
        out.push_str(block);
        if header.is_some() {
            prev_header = header;
        }
    }
    out
}

fn extract_header_field(block: &str, field: &str) -> Option<String> {
    for line in block.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(rest) = rest.trim_start().strip_prefix('=') {
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// Deterministic sort key for `[[ignored]]` entries.
///
/// Order (low first): whole-file skips → entity_type → scope (global < file < line)
/// → path → text/pattern. Entries with no entity_type go after those that
/// have them. Scope here is the effective (possibly-inferred) scope.
fn sort_key(e: &IgnoreEntry) -> (u8, String, u8, String, String) {
    let is_whole_file = e.kind.as_deref() == Some("file");
    let tier = if is_whole_file { 0 } else { 1 };
    let entity = e.entity_type.clone().unwrap_or_default();
    let scope_rank = match effective_scope(e) {
        Scope::Global => 0,
        Scope::File => 1,
        Scope::Line => 2,
    };
    let path = e.path.clone().unwrap_or_default();
    let text = e
        .regex
        .clone()
        .or_else(|| e.text.clone())
        .unwrap_or_default();
    (tier, entity, scope_rank, path, text)
}

/// Return `true` if this ignore entry's match criteria apply to the finding.
/// Precedence: `match` regex > `text` glob > `text` literal+per-entity rules.
/// (Mutual exclusion is enforced at load time, so `text` and `match` are
/// never both set on a single entry.)
fn matches_criteria(entry: &IgnoreEntry, c: &CompiledMatchers, f: &Finding) -> bool {
    if let Some(re) = c.regex.as_ref() {
        return re.is_match(&f.text);
    }
    if let Some(g) = c.text.as_ref() {
        // URL findings get the host-aware `*.host` semantics first; only
        // if that doesn't match do we fall through to the generic glob over
        // the full URL text. Lets `text = "*.metriport.com"` match
        // `https://api.metriport.com/foo` (which a vanilla glob couldn't).
        if f.entity_type == "URL" {
            if let Some(t) = entry.text.as_deref() {
                if url_wildcard_matches(t, &f.text) {
                    return true;
                }
            }
        }
        return g.matches(&f.text);
    }
    text_matches(entry, f)
}

/// Pull the host out of a URL-ish string. Handles bare hosts (`github.com`),
/// schemed URLs (`https://github.com/foo`), userinfo prefixes
/// (`https://user@github.com`), ports (`github.com:8080`), and the trailing
/// path/query/fragment. Lowercased and stripped of any trailing root dot so
/// callers can use it as a stable comparison key.
pub fn extract_url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let after_user = after_scheme.rsplit_once('@').map(|(_, r)| r).unwrap_or(after_scheme);
    let host_end = after_user
        .find(|c: char| matches!(c, '/' | '?' | '#' | ':'))
        .unwrap_or(after_user.len());
    let host = &after_user[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host.trim_end_matches('.').to_ascii_lowercase())
    }
}

/// Test the URL `*.host` wildcard convention against a finding's URL.
/// `*.github.com` matches `github.com` itself plus any subdomain;
/// suffix-spoofing (`notgithub.com`) is rejected by requiring a dot
/// boundary. Returns false (deferring to plain text match) for non-wildcard
/// inputs or unparseable URLs.
fn url_wildcard_matches(pattern: &str, finding_text: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    let Some(host) = extract_url_host(finding_text) else {
        return false;
    };
    let suffix = suffix.to_ascii_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Port of phi-scan's text-matching logic in `_is_ignored`. A missing text
/// means "any text matches". All comparisons are case-insensitive — email
/// casing is canonically insensitive, and it's annoying to get bitten by
/// `Admin@Example.com` vs `admin@example.com` for other entity types too.
///
/// Per-entity wildcards layered on top of the literal compare:
/// - EMAIL_ADDRESS: leading `@` matches by domain, trailing `@` by username.
/// - URL: `*.host` matches the apex host plus any subdomain (dot-boundary
///   suffix, so `notgithub.com` does not match `*.github.com`).
fn text_matches(entry: &IgnoreEntry, f: &Finding) -> bool {
    let Some(txt) = entry.text.as_deref() else {
        return true;
    };
    if txt.eq_ignore_ascii_case(&f.text) {
        return true;
    }
    if f.entity_type == "EMAIL_ADDRESS" {
        let finding_lower = f.text.to_ascii_lowercase();
        let txt_lower = txt.to_ascii_lowercase();
        if txt_lower.starts_with('@') && finding_lower.ends_with(&txt_lower) {
            return true;
        }
        if txt_lower.ends_with('@') && finding_lower.starts_with(&txt_lower) {
            return true;
        }
    }
    if f.entity_type == "URL" && url_wildcard_matches(txt, &f.text) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_finding(entity: &str, text: &str, file: &str, line: u32) -> Finding {
        Finding {
            file: file.to_string(),
            line_num: line,
            col_start: 0,
            col_end: text.len() as u32,
            entity_type: entity.to_string(),
            text: text.to_string(),
            score: 1.0,
            line_content: text.to_string(),
        }
    }

    fn with_entries(entries: Vec<IgnoreEntry>) -> Ignorelist {
        let mut list = Ignorelist::default();
        for e in entries {
            list.append(e);
        }
        list
    }

    #[test]
    fn text_match_is_case_insensitive() {
        let entry = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            text: Some("admin@example.com".into()),
            ..Default::default()
        };
        let f = mk_finding("EMAIL_ADDRESS", "Admin@Example.COM", "x", 1);
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&f));
    }

    #[test]
    fn email_domain_wildcard_matches_by_domain() {
        let entry = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            text: Some("@askclara.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "user@askclara.com",
            "x",
            1
        )));
        assert!(!list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "user@other.com",
            "x",
            1
        )));
    }

    #[test]
    fn email_username_wildcard_matches_by_user() {
        let entry = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            text: Some("noreply@".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "noreply@any.tld",
            "x",
            1
        )));
    }

    #[test]
    fn pattern_regex_takes_precedence_over_text() {
        let entry = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            regex: Some(r"@\w+\.askclara\.com$".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "a@staging.askclara.com",
            "x",
            1
        )));
        assert!(!list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "a@example.com",
            "x",
            1
        )));
    }

    #[test]
    fn scope_file_limits_to_single_file() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("file".into()),
            path: Some("docs/a.md".into()),
            text: Some("https://example.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://example.com", "docs/a.md", 1)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://example.com", "docs/b.md", 1)));
    }

    #[test]
    fn scope_line_limits_to_file_and_line() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("line".into()),
            path: Some("x".into()),
            line: Some("42".into()),
            text: Some("https://example.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://example.com", "x", 42)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://example.com", "x", 43)));
    }

    #[test]
    fn whole_file_skip_ignores_path_entirely() {
        let entry = IgnoreEntry {
            kind: Some("file".into()),
            path: Some("vendor/bundle.js".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_file_skipped("vendor/bundle.js"));
        assert!(!list.is_file_skipped("src/app.js"));
    }

    #[test]
    fn path_supports_glob_syntax() {
        let entry = IgnoreEntry {
            entity_type: Some("IP_ADDRESS".into()),
            path: Some("documentation/**".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding(
            "IP_ADDRESS",
            "1.2.3.4",
            "documentation/api/foo.md",
            1,
        )));
        assert!(list.is_ignored(&mk_finding(
            "IP_ADDRESS",
            "1.2.3.4",
            "documentation/bar.md",
            1,
        )));
        assert!(!list.is_ignored(&mk_finding("IP_ADDRESS", "1.2.3.4", "src/app.py", 1)));
    }

    #[test]
    fn whole_file_skip_supports_glob() {
        let entry = IgnoreEntry {
            kind: Some("file".into()),
            path: Some("vendor/**".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_file_skipped("vendor/bundle.js"));
        assert!(list.is_file_skipped("vendor/sub/thing.min.js"));
        assert!(!list.is_file_skipped("src/app.py"));
    }

    #[test]
    fn scope_inferred_from_path_and_line() {
        // path alone → file scope
        let e_file = IgnoreEntry {
            entity_type: Some("URL".into()),
            path: Some("a.py".into()),
            text: Some("https://x".into()),
            ..Default::default()
        };
        // path + line → line scope
        let e_line = IgnoreEntry {
            entity_type: Some("URL".into()),
            path: Some("a.py".into()),
            line: Some("3".into()),
            text: Some("https://x".into()),
            ..Default::default()
        };
        // neither → global scope
        let e_global = IgnoreEntry {
            entity_type: Some("URL".into()),
            text: Some("https://x".into()),
            ..Default::default()
        };

        let file_list = with_entries(vec![e_file]);
        assert!(file_list.is_ignored(&mk_finding("URL", "https://x", "a.py", 1)));
        assert!(!file_list.is_ignored(&mk_finding("URL", "https://x", "b.py", 1)));

        let line_list = with_entries(vec![e_line]);
        assert!(line_list.is_ignored(&mk_finding("URL", "https://x", "a.py", 3)));
        assert!(!line_list.is_ignored(&mk_finding("URL", "https://x", "a.py", 4)));

        let global_list = with_entries(vec![e_global]);
        assert!(global_list.is_ignored(&mk_finding("URL", "https://x", "any.py", 99)));
    }

    #[test]
    fn file_field_is_accepted_as_alias_for_path() {
        // Backward compat: old ignorelists that wrote `file = "..."` still load.
        let text = r#"
[[ignored]]
entity_type = "URL"
file = "legacy/thing.md"
text = "https://x"
"#;
        let dir = std::env::temp_dir().join(format!("ttops-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phi.toml");
        std::fs::write(&path, text).unwrap();
        let list = Ignorelist::load_or_empty(&path).unwrap();
        assert!(list.is_ignored(&mk_finding("URL", "https://x", "legacy/thing.md", 1)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_text_matches_any() {
        // `text` omitted means "ignore all findings of this entity in this file".
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("file".into()),
            path: Some("x".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://a.com", "x", 1)));
        assert!(list.is_ignored(&mk_finding("URL", "https://b.com", "x", 2)));
    }

    #[test]
    fn entities_disable_is_read_from_toml() {
        let text = r#"
[entities]
URL = false
MAC_ADDRESS = true
"#;
        let dir = std::env::temp_dir().join(format!("ttops-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phi.toml");
        std::fs::write(&path, text).unwrap();
        let list = Ignorelist::load_or_empty(&path).unwrap();
        assert!(list.is_entity_disabled("URL"));
        assert!(!list.is_entity_disabled("MAC_ADDRESS"));
        assert!(!list.is_entity_disabled("EMAIL_ADDRESS"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extract_url_host_handles_common_shapes() {
        assert_eq!(extract_url_host("https://github.com/foo").as_deref(), Some("github.com"));
        assert_eq!(extract_url_host("http://api.github.com:8080/x").as_deref(), Some("api.github.com"));
        assert_eq!(extract_url_host("github.com").as_deref(), Some("github.com"));
        assert_eq!(extract_url_host("github.com/path").as_deref(), Some("github.com"));
        assert_eq!(extract_url_host("https://user@example.org/x").as_deref(), Some("example.org"));
        // Returned host is normalized to lowercase.
        assert_eq!(extract_url_host("HTTPS://Example.COM/").as_deref(), Some("example.com"));
        assert_eq!(extract_url_host(""), None);
    }

    #[test]
    fn line_spec_parses_singletons_lists_and_ranges() {
        let s = LineSpec::parse("1,5,8..29").unwrap();
        assert!(s.contains(1));
        assert!(!s.contains(2));
        assert!(s.contains(5));
        assert!(!s.contains(6));
        assert!(s.contains(8));
        assert!(s.contains(15));
        assert!(s.contains(29)); // inclusive end
        assert!(!s.contains(30));

        let single = LineSpec::parse("42").unwrap();
        assert!(single.contains(42));
        assert!(!single.contains(41));

        // Whitespace around bits is fine.
        let spaced = LineSpec::parse(" 1 , 3..5 , 9 ").unwrap();
        assert!(spaced.contains(4));
    }

    #[test]
    fn line_spec_rejects_garbage() {
        assert!(LineSpec::parse("abc").is_err());
        assert!(LineSpec::parse("5..3").is_err()); // start > end
        assert!(LineSpec::parse("").is_err()); // empty after trim
        assert!(LineSpec::parse("5..").is_err()); // missing end
    }

    #[test]
    fn line_range_in_ignore_entry() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            path: Some("docs/api.md".into()),
            line: Some("8..12,20".into()),
            text: Some("https://example.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://example.com", "docs/api.md", 8)));
        assert!(list.is_ignored(&mk_finding("URL", "https://example.com", "docs/api.md", 12)));
        assert!(list.is_ignored(&mk_finding("URL", "https://example.com", "docs/api.md", 20)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://example.com", "docs/api.md", 7)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://example.com", "docs/api.md", 13)));
    }

    #[test]
    fn text_glob_matches_full_finding_text() {
        // Anchored: must match the whole finding text.
        let entry = IgnoreEntry {
            entity_type: Some("US_SSN".into()),
            scope: Some("global".into()),
            text: Some("123-45-*".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("US_SSN", "123-45-6789", "x", 1)));
        assert!(!list.is_ignored(&mk_finding("US_SSN", "999-45-6789", "x", 1)));
    }

    #[test]
    fn textglob_false_forces_literal_compare() {
        // Without `textglob = false`, the `*` would make this a glob and
        // match any 4-digit suffix. With it off, only the literal string
        // matches.
        let entry = IgnoreEntry {
            entity_type: Some("US_SSN".into()),
            scope: Some("global".into()),
            text: Some("123-45-*".into()),
            textglob: Some(false),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("US_SSN", "123-45-*", "x", 1)));
        assert!(!list.is_ignored(&mk_finding("US_SSN", "123-45-6789", "x", 1)));
    }

    #[test]
    fn text_glob_double_star_crosses_segments() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            text: Some("**/internal/**".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding(
            "URL",
            "https://x.com/foo/bar/internal/y/z",
            "f",
            1
        )));
    }

    #[test]
    fn pattern_field_is_alias_for_match() {
        // Existing files using `pattern = "..."` continue to load.
        let text = r#"
[[ignored]]
entity_type = "EMAIL_ADDRESS"
pattern     = '@staging\.askclara\.com$'
"#;
        let dir = std::env::temp_dir().join(format!("ttops-pat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phi.toml");
        std::fs::write(&path, text).unwrap();
        let list = Ignorelist::load_or_empty(&path).unwrap();
        assert!(list.is_ignored(&mk_finding(
            "EMAIL_ADDRESS",
            "user@staging.askclara.com",
            "f",
            1
        )));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mutually_exclusive_text_and_match_errors() {
        let text = r#"
[[ignored]]
entity_type = "URL"
text  = "foo"
match = "bar"
"#;
        let dir = std::env::temp_dir().join(format!("ttops-excl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phi.toml");
        std::fs::write(&path, text).unwrap();
        let err = Ignorelist::load_or_empty(&path).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("text") && msg.contains("match"), "got: {msg}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_top_level_key_errors_loudly() {
        // Regression: `[enabled]` (vs the real `[entities]`) used to be
        // silently dropped, leaving disable-rules unenforced. With
        // `deny_unknown_fields`, the load returns an error pinpointing
        // the offending key.
        let text = r#"
[enabled]
ORGANIZATION = false
"#;
        let dir = std::env::temp_dir().join(format!("ttops-deny-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phi.toml");
        std::fs::write(&path, text).unwrap();
        let err = Ignorelist::load_or_empty(&path).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("enabled"), "error should mention the bad key, got: {msg}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn url_text_wildcard_matches_subdomains_and_apex() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("global".into()),
            text: Some("*.metriport.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://metriport.com/", "x", 1)));
        assert!(list.is_ignored(&mk_finding("URL", "https://api.metriport.com/x", "x", 1)));
        assert!(list.is_ignored(&mk_finding("URL", "https://a.b.metriport.com/y", "x", 1)));
        // Suffix-spoofing must not match.
        assert!(!list.is_ignored(&mk_finding("URL", "https://notmetriport.com/", "x", 1)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://example.com/metriport.com", "x", 1)));
    }

    #[test]
    fn url_text_wildcard_only_applies_to_url_entity() {
        // `*.host` text on a non-URL entity falls through to literal compare,
        // so it shouldn't accidentally match unrelated finding types.
        let entry = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            text: Some("*.metriport.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(!list.is_ignored(&mk_finding("EMAIL_ADDRESS", "u@metriport.com", "x", 1)));
    }

    #[test]
    fn url_text_wildcard_with_file_scope() {
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            path: Some("docs/**".into()),
            text: Some("*.github.com".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_ignored(&mk_finding("URL", "https://api.github.com", "docs/a.md", 1)));
        assert!(!list.is_ignored(&mk_finding("URL", "https://api.github.com", "src/app.py", 1)));
    }

    #[test]
    fn sort_key_puts_whole_file_skips_first() {
        let whole = IgnoreEntry {
            kind: Some("file".into()),
            path: Some("a".into()),
            ..Default::default()
        };
        let regular = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("global".into()),
            text: Some("https://x".into()),
            ..Default::default()
        };
        let mut v = [regular.clone(), whole.clone()];
        v.sort_by_key(sort_key);
        assert_eq!(v[0].kind.as_deref(), Some("file"));
    }

    #[test]
    fn sort_key_orders_by_entity_then_scope() {
        let email_global = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("global".into()),
            text: Some("a".into()),
            ..Default::default()
        };
        let url_file = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("file".into()),
            path: Some("f".into()),
            text: Some("b".into()),
            ..Default::default()
        };
        let email_line = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("line".into()),
            path: Some("f".into()),
            line: Some("1".into()),
            text: Some("c".into()),
            ..Default::default()
        };
        let mut v = [url_file, email_line, email_global];
        v.sort_by_key(sort_key);
        // EMAIL_ADDRESS group first (alphabetical), global (rank 0) before line (rank 2).
        assert_eq!(v[0].entity_type.as_deref(), Some("EMAIL_ADDRESS"));
        assert_eq!(v[0].scope.as_deref(), Some("global"));
        assert_eq!(v[1].entity_type.as_deref(), Some("EMAIL_ADDRESS"));
        assert_eq!(v[1].scope.as_deref(), Some("line"));
        assert_eq!(v[2].entity_type.as_deref(), Some("URL"));
    }
}
