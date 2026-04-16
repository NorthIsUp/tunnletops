use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// Matches the phi.yaml semantic model:
/// - `type: "file"` entries skip the entire file (whole-file ignore).
/// - `scope: "line"` matches on (file, line_num, entity_type, text).
/// - `scope: "file"` matches on (file, entity_type, text).
/// - `scope: "global"` matches on (entity_type, text).
/// - Missing `text` is treated as "any text" (so you can ignore
///   all findings of a given type in a file).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnoreEntry {
    // Field order here is the TOML serialization order. We put the "what
    // kind of entry is this?" fields first (type for whole-file skips;
    // entity_type for regular), then narrowing scope/file/line, then the
    // matcher (text / pattern). Makes each [[ignored]] block's first
    // visible line tell you what it's about.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Optional regex applied to the finding's text. When set, takes
    /// precedence over `text`. Use TOML literal strings (single quotes)
    /// to avoid double-escaping backslashes:
    ///
    /// ```toml
    /// pattern = '@\w+\.askclara\.com'
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
pub struct Ignorelist {
    entries: Vec<IgnoreEntry>,
    /// Parallel to `entries`: compiled regex for entries with `pattern` set.
    compiled_patterns: Vec<Option<Regex>>,
    whole_file_skips: HashSet<String>,
    disabled_entities: HashSet<String>,
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
            if e.kind.as_deref() == Some("file") {
                if let Some(f) = &e.file {
                    out.whole_file_skips.insert(f.clone());
                }
            }
            let compiled = e.pattern.as_ref().and_then(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(err) => {
                    eprintln!(
                        "warning: invalid pattern in {}: {} (skipping this ignore rule)",
                        path.display(),
                        err
                    );
                    None
                }
            });
            out.entries.push(e);
            out.compiled_patterns.push(compiled);
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
        self.whole_file_skips.contains(file)
    }

    pub fn is_ignored(&self, f: &Finding) -> bool {
        for (entry, compiled) in self.entries.iter().zip(self.compiled_patterns.iter()) {
            if entry.kind.as_deref() == Some("file") {
                if entry.file.as_deref() == Some(f.file.as_str()) {
                    return true;
                }
                continue;
            }
            if let Some(et) = &entry.entity_type {
                if et != &f.entity_type {
                    continue;
                }
            }
            if !matches_criteria(entry, compiled.as_ref(), f) {
                continue;
            }
            match entry.scope.as_deref() {
                Some("line") => {
                    if entry.file.as_deref() == Some(f.file.as_str())
                        && entry.line.as_deref() == Some(f.line_num.to_string().as_str())
                    {
                        return true;
                    }
                }
                Some("file") => {
                    if entry.file.as_deref() == Some(f.file.as_str()) {
                        return true;
                    }
                }
                Some("global") => {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    pub fn append(&mut self, entry: IgnoreEntry) {
        if entry.kind.as_deref() == Some("file") {
            if let Some(file) = &entry.file {
                self.whole_file_skips.insert(file.clone());
            }
        }
        let compiled = entry.pattern.as_ref().and_then(|p| Regex::new(p).ok());
        self.entries.push(entry);
        self.compiled_patterns.push(compiled);
    }

    #[allow(dead_code)]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut ignored = self.entries.clone();
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
/// → file → text/pattern. Entries with no entity_type or no scope go after
/// those that have them because `Option::None` compares less than `Some(...)`
/// — we invert that for tier so whole-file skips come FIRST.
fn sort_key(e: &IgnoreEntry) -> (u8, String, u8, String, String) {
    let is_whole_file = e.kind.as_deref() == Some("file");
    let tier = if is_whole_file { 0 } else { 1 };
    let entity = e.entity_type.clone().unwrap_or_default();
    let scope_rank = match e.scope.as_deref() {
        Some("global") => 0,
        Some("file") => 1,
        Some("line") => 2,
        _ => 3,
    };
    let file = e.file.clone().unwrap_or_default();
    let text = e
        .pattern
        .clone()
        .or_else(|| e.text.clone())
        .unwrap_or_default();
    (tier, entity, scope_rank, file, text)
}

/// Return `true` if this ignore entry's match criteria apply to the finding.
/// `pattern` (precompiled regex) takes precedence over `text` when set.
fn matches_criteria(entry: &IgnoreEntry, compiled: Option<&Regex>, f: &Finding) -> bool {
    if let Some(re) = compiled {
        return re.is_match(&f.text);
    }
    text_matches(entry, f)
}

/// Port of phi-scan's text-matching logic in `_is_ignored`. A missing text
/// means "any text matches". All comparisons are case-insensitive — email
/// casing is canonically insensitive, and it's annoying to get bitten by
/// `Admin@Example.com` vs `admin@example.com` for other entity types too.
/// For EMAIL_ADDRESS, a leading `@` matches by domain and a trailing `@`
/// matches by username.
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
            pattern: Some(r"@\w+\.askclara\.com$".into()),
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
            file: Some("docs/a.md".into()),
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
            file: Some("x".into()),
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
            file: Some("vendor/bundle.js".into()),
            ..Default::default()
        };
        let list = with_entries(vec![entry]);
        assert!(list.is_file_skipped("vendor/bundle.js"));
        assert!(!list.is_file_skipped("src/app.js"));
    }

    #[test]
    fn missing_text_matches_any() {
        // `text` omitted means "ignore all findings of this entity in this file".
        let entry = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("file".into()),
            file: Some("x".into()),
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
    fn sort_key_puts_whole_file_skips_first() {
        let whole = IgnoreEntry {
            kind: Some("file".into()),
            file: Some("a".into()),
            ..Default::default()
        };
        let regular = IgnoreEntry {
            entity_type: Some("URL".into()),
            scope: Some("global".into()),
            text: Some("https://x".into()),
            ..Default::default()
        };
        let mut v = vec![regular.clone(), whole.clone()];
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
            file: Some("f".into()),
            text: Some("b".into()),
            ..Default::default()
        };
        let email_line = IgnoreEntry {
            entity_type: Some("EMAIL_ADDRESS".into()),
            scope: Some("line".into()),
            file: Some("f".into()),
            line: Some("1".into()),
            text: Some("c".into()),
            ..Default::default()
        };
        let mut v = vec![url_file, email_line, email_global];
        v.sort_by_key(sort_key);
        // EMAIL_ADDRESS group first (alphabetical), global (rank 0) before line (rank 2).
        assert_eq!(v[0].entity_type.as_deref(), Some("EMAIL_ADDRESS"));
        assert_eq!(v[0].scope.as_deref(), Some("global"));
        assert_eq!(v[1].entity_type.as_deref(), Some("EMAIL_ADDRESS"));
        assert_eq!(v[1].scope.as_deref(), Some("line"));
        assert_eq!(v[2].entity_type.as_deref(), Some("URL"));
    }
}
