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
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<String>,
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    /// Optional regex applied to the finding's text. When set, takes
    /// precedence over `text`. Use TOML literal strings (single quotes)
    /// to avoid double-escaping backslashes:
    ///
    /// ```toml
    /// pattern = '@\w+\.askclara\.com'
    /// ```
    #[serde(default)]
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
        let file: IgnorelistFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
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
