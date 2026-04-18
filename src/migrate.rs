use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ignorelist::{IgnoreEntry, IgnorelistFile};

/// Shape of the legacy phi.yaml file: a top-level `ignored:` map whose
/// keys are arbitrary strings and whose values describe the ignore entry.
#[derive(Debug, Deserialize)]
struct LegacyFile {
    #[serde(default)]
    ignored: BTreeMap<String, LegacyEntry>,
}

#[derive(Debug, Deserialize)]
struct LegacyEntry {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    line: Option<serde_yaml::Value>,
    #[serde(default)]
    entity_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

/// Parse a legacy `phi.yaml` into the in-memory `IgnorelistFile`.
/// Used by both the `migrate` subcommand and the YAML fallback in
/// `Ignorelist::load_or_empty`.
pub fn load_legacy_yaml(yaml_text: &str) -> Result<IgnorelistFile> {
    let legacy: LegacyFile = serde_yaml::from_str(yaml_text).context("parsing legacy YAML")?;
    // phi-scan's `_is_ignored` falls back to the arbitrary top-level YAML key
    // when a `type: file` entry has no explicit `file:` field. Preserve that.
    let mut entries: Vec<IgnoreEntry> = Vec::with_capacity(legacy.ignored.len());
    for (key, e) in legacy.ignored {
        let path = e.file.or_else(|| {
            if e.kind.as_deref() == Some("file") {
                Some(key.clone())
            } else {
                None
            }
        });
        entries.push(IgnoreEntry {
            kind: e.kind,
            scope: e.scope,
            path,
            line: e.line.and_then(|v| match v {
                serde_yaml::Value::String(s) => Some(s),
                serde_yaml::Value::Number(n) => Some(n.to_string()),
                _ => None,
            }),
            entity_type: e.entity_type,
            text: e.text,
            textglob: None,
            regex: None,
        });
    }
    Ok(IgnorelistFile {
        ignored: entries,
        entities: Default::default(),
    })
}

pub fn migrate(input: &Path, output: &Path) -> Result<()> {
    let yaml_text =
        fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let toml_file =
        load_legacy_yaml(&yaml_text).with_context(|| format!("parsing {}", input.display()))?;
    let toml_text = toml::to_string_pretty(&toml_file).context("serializing tunneltops TOML")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(output, toml_text).with_context(|| format!("writing {}", output.display()))?;

    eprintln!(
        "migrated {} -> {} ({} entries)",
        input.display(),
        output.display(),
        toml_file.ignored.len()
    );
    Ok(())
}
