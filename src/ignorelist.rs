use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnorelistFile {
    #[serde(default)]
    pub ignored: Vec<IgnoreEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct Ignorelist {
    entries: Vec<IgnoreEntry>,
    whole_file_skips: HashSet<String>,
}

impl Ignorelist {
    pub fn load_or_empty(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let file: IgnorelistFile = toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        let mut out = Self::default();
        for e in file.ignored {
            if e.kind.as_deref() == Some("file") {
                if let Some(f) = &e.file {
                    out.whole_file_skips.insert(f.clone());
                }
            }
            out.entries.push(e);
        }
        Ok(out)
    }

    pub fn is_file_skipped(&self, file: &str) -> bool {
        self.whole_file_skips.contains(file)
    }

    pub fn is_ignored(&self, f: &Finding) -> bool {
        for entry in &self.entries {
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
            if !text_matches(entry, f) {
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
        self.entries.push(entry);
    }

    #[allow(dead_code)]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let file = IgnorelistFile {
            ignored: self.entries.clone(),
        };
        let text = toml::to_string_pretty(&file).context("serializing ignorelist")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

/// Port of phi-scan's text-matching logic in `_is_ignored`. A missing text
/// means "any text matches"; for EMAIL_ADDRESS, a leading `@` matches by
/// domain and a trailing `@` matches by username (both case-insensitive).
fn text_matches(entry: &IgnoreEntry, f: &Finding) -> bool {
    let Some(txt) = entry.text.as_deref() else {
        return true;
    };
    if txt == f.text {
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
