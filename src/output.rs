use std::fs;
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::finding::{FileOutcome, Finding};
use crate::ignorelist::{IgnoreEntry, Ignorelist};
use crate::Format;

pub struct Formatter {
    format: Format,
    only_issues: bool,
}

impl Formatter {
    pub fn new(format: Format, only_issues: bool) -> Self {
        Self {
            format,
            only_issues,
        }
    }

    /// Per-file streaming status line — matches phi-scan's run_without_progress output.
    /// In `github` format we suppress it: GitHub Actions parses stdout for
    /// `::error::` annotations and the streaming lines would pollute the output.
    pub fn emit_file_status(&self, outcome: &FileOutcome) {
        if outcome.skipped {
            return;
        }
        if matches!(self.format, Format::Github) {
            return;
        }
        let n = outcome.findings.len();
        let ign = outcome.ignored_count;
        let mut parts: Vec<String> = Vec::new();
        if n > 0 {
            parts.push(format!("{} {}", n, plural(n, "finding", "findings")));
        }
        if ign > 0 {
            parts.push(format!("{} ignored", ign));
        }
        if !parts.is_empty() {
            println!("{}: {}", outcome.file, parts.join(", "));
        } else if !self.only_issues {
            println!("{}: ok", outcome.file);
        }
    }

    pub fn emit_summary(&self, outcomes: &[FileOutcome]) -> Result<()> {
        let all: Vec<&Finding> = outcomes.iter().flat_map(|o| o.findings.iter()).collect();
        match self.format {
            Format::Plain => emit_plain(&all),
            Format::Github => emit_github(&all),
            Format::Tui => emit_tui(&all),
        }
        Ok(())
    }
}

fn emit_plain(findings: &[&Finding]) {
    for f in findings {
        println!(
            "{}:{}:{}: {} (score: {:.2}) {:?}",
            f.file,
            f.line_num,
            f.col_start + 1,
            f.entity_type,
            f.score,
            f.text
        );
    }
}

fn emit_github(findings: &[&Finding]) {
    for f in findings {
        println!(
            "::error file={},line={},col={},endColumn={},title=PHI/PII ({})::Found {} with score {:.2}: {:?}",
            f.file,
            f.line_num,
            f.col_start + 1,
            f.col_end + 1,
            f.entity_type,
            f.entity_type,
            f.score,
            f.text
        );
    }
}

fn emit_tui(findings: &[&Finding]) {
    for f in findings {
        render_diagnostic(f);
        println!();
    }
}

fn render_diagnostic(f: &Finding) {
    let stripped = f.line_content.trim_start();
    let indent = f.line_content.len() - stripped.len();
    let col = f.col_start as usize - indent.min(f.col_start as usize);
    let span = (f.col_end.saturating_sub(f.col_start).max(1)) as usize;
    let gutter = f.line_num.to_string().len();
    let g = " ".repeat(gutter + 1);
    let ln = format!("{:>width$}", f.line_num, width = gutter);
    let before = &stripped.get(..col).unwrap_or("");
    let match_slice = &stripped.get(col..col + span).unwrap_or("");
    let after = &stripped.get(col + span..).unwrap_or("");
    let mid = col + span / 2;
    println!(
        "{}{} {}:{}:{}",
        g,
        "┌─".cyan().bold(),
        f.file,
        f.line_num,
        f.col_start + 1
    );
    println!(
        "{} {} {}{}{}",
        ln,
        "│".cyan().bold(),
        before,
        match_slice.red().bold().underline(),
        after
    );
    println!(
        "{}{} {}{}",
        g,
        "·".cyan().bold(),
        " ".repeat(mid),
        "▲".magenta().bold()
    );
    println!(
        "{}{} {}{} {} {}",
        g,
        "·".cyan().bold(),
        " ".repeat(mid),
        "└──".magenta().bold(),
        f.entity_type.magenta().bold(),
        format!("(σ {:.1})", f.score).dimmed()
    );
}

fn plural<'a>(n: usize, singular: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        singular
    } else {
        many
    }
}

/// Interactive triage. Walks unique `(file, entity_type, text)` findings one
/// at a time; each prompt returns an action that updates the in-memory
/// `Ignorelist`. On quit (`q`) we still save anything already accepted.
///
/// Keys:
///   y / Enter — ignore this finding in this file (`scope = "file"`)
///   g         — ignore globally (`scope = "global"`, any file)
///   n         — keep the finding (don't add an ignore rule)
///   a         — accept the rest as file-scope (remaining auto-ignore)
///   q         — save what's been accepted so far and stop
///   ?         — show the help line
pub fn fix_interactive(outcomes: &[FileOutcome], ignorelist_path: &str) -> Result<()> {
    let mut ignorelist = Ignorelist::load_or_empty(ignorelist_path)
        .with_context(|| format!("loading {}", ignorelist_path))?;

    let mut seen: std::collections::HashSet<(String, String, String)> = Default::default();
    let mut items: Vec<&Finding> = Vec::new();
    for outcome in outcomes {
        for f in &outcome.findings {
            let key = (f.file.clone(), f.entity_type.clone(), f.text.clone());
            if seen.insert(key) {
                items.push(f);
            }
        }
    }

    let total = items.len();
    if total == 0 {
        eprintln!("no findings to triage");
        return Ok(());
    }

    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut added = 0usize;
    let mut kept = 0usize;
    let mut accept_rest = false;

    for (i, f) in items.iter().enumerate() {
        render_diagnostic_stderr(f);

        if accept_rest {
            ignorelist.append(file_scope_entry(f));
            added += 1;
            continue;
        }

        loop {
            eprint!(
                "  [{}/{}] {} {} {} ",
                i + 1,
                total,
                "(y)ignore-file".green(),
                "·".dimmed(),
                "(g)lobal (n)keep (a)ll-remaining (q)uit >".dimmed(),
            );
            io::stderr().flush().ok();

            let mut line = String::new();
            if stdin.read_line(&mut line)? == 0 {
                eprintln!();
                break;
            }
            match line.trim() {
                "y" | "Y" | "" => {
                    ignorelist.append(file_scope_entry(f));
                    added += 1;
                    break;
                }
                "g" | "G" => {
                    ignorelist.append(global_scope_entry(f));
                    added += 1;
                    break;
                }
                "n" | "N" => {
                    kept += 1;
                    break;
                }
                "a" | "A" => {
                    ignorelist.append(file_scope_entry(f));
                    added += 1;
                    accept_rest = true;
                    break;
                }
                "q" | "Q" => {
                    save_if_added(&ignorelist, ignorelist_path, added)?;
                    eprintln!(
                        "quit — ignored {}, kept {}, {} not reviewed",
                        added,
                        kept,
                        total - (i + 1),
                    );
                    return Ok(());
                }
                "?" => {
                    eprintln!(
                        "  y=ignore in this file, g=global, n=keep, a=accept all remaining, q=quit"
                    );
                }
                _ => {
                    eprintln!("  unknown key (try ? for help)");
                }
            }
        }
    }

    save_if_added(&ignorelist, ignorelist_path, added)?;
    eprintln!("ignored {}, kept {}", added, kept);
    Ok(())
}

fn file_scope_entry(f: &Finding) -> IgnoreEntry {
    IgnoreEntry {
        kind: None,
        scope: Some("file".to_string()),
        file: Some(f.file.clone()),
        line: None,
        entity_type: Some(f.entity_type.clone()),
        text: Some(f.text.clone()),
        pattern: None,
    }
}

fn global_scope_entry(f: &Finding) -> IgnoreEntry {
    IgnoreEntry {
        kind: None,
        scope: Some("global".to_string()),
        file: None,
        line: None,
        entity_type: Some(f.entity_type.clone()),
        text: Some(f.text.clone()),
        pattern: None,
    }
}

fn save_if_added(ignorelist: &Ignorelist, ignorelist_path: &str, added: usize) -> Result<()> {
    if added == 0 {
        return Ok(());
    }
    if let Some(parent) = std::path::Path::new(ignorelist_path).parent() {
        fs::create_dir_all(parent).ok();
    }
    ignorelist.save(ignorelist_path)?;
    Ok(())
}

/// Same layout as `render_diagnostic` but writes to stderr so it doesn't
/// intermingle with stdout summary output during interactive triage.
fn render_diagnostic_stderr(f: &Finding) {
    let stripped = f.line_content.trim_start();
    let indent = f.line_content.len() - stripped.len();
    let col = f.col_start as usize - indent.min(f.col_start as usize);
    let span = (f.col_end.saturating_sub(f.col_start).max(1)) as usize;
    let gutter = f.line_num.to_string().len();
    let g = " ".repeat(gutter + 1);
    let ln = format!("{:>width$}", f.line_num, width = gutter);
    let before = &stripped.get(..col).unwrap_or("");
    let match_slice = &stripped.get(col..col + span).unwrap_or("");
    let after = &stripped.get(col + span..).unwrap_or("");
    let mid = col + span / 2;
    eprintln!(
        "{}{} {}:{}:{}",
        g,
        "┌─".cyan().bold(),
        f.file,
        f.line_num,
        f.col_start + 1
    );
    eprintln!(
        "{} {} {}{}{}",
        ln,
        "│".cyan().bold(),
        before,
        match_slice.red().bold().underline(),
        after
    );
    eprintln!(
        "{}{} {}{}",
        g,
        "·".cyan().bold(),
        " ".repeat(mid),
        "▲".magenta().bold()
    );
    eprintln!(
        "{}{} {}{} {} {}",
        g,
        "·".cyan().bold(),
        " ".repeat(mid),
        "└──".magenta().bold(),
        f.entity_type.magenta().bold(),
        format!("(σ {:.1})", f.score).dimmed()
    );
}

pub fn fix_accept_all(outcomes: &[FileOutcome], ignorelist_path: &str) -> Result<()> {
    let mut ignorelist = Ignorelist::load_or_empty(ignorelist_path)
        .with_context(|| format!("loading {}", ignorelist_path))?;
    let mut seen: std::collections::HashSet<(String, String, String)> = Default::default();
    let mut added = 0usize;
    for outcome in outcomes {
        for f in &outcome.findings {
            // Use `scope = "file"` (not "line") so the ignore survives when
            // the line shifts from edits above it. Matches any occurrence of
            // `(entity_type, text)` in this file. Dedupe so we don't write
            // the same entry once per occurrence.
            let key = (f.file.clone(), f.entity_type.clone(), f.text.clone());
            if !seen.insert(key) {
                continue;
            }
            ignorelist.append(IgnoreEntry {
                kind: None,
                scope: Some("file".to_string()),
                file: Some(f.file.clone()),
                line: None,
                entity_type: Some(f.entity_type.clone()),
                text: Some(f.text.clone()),
                pattern: None,
            });
            added += 1;
        }
    }
    if added > 0 {
        // Ensure parent dir exists (e.g. .baselines/).
        if let Some(parent) = std::path::Path::new(ignorelist_path).parent() {
            fs::create_dir_all(parent).ok();
        }
        ignorelist.save(ignorelist_path)?;
    }
    eprintln!("ignored {} {}", added, plural(added, "finding", "findings"));
    Ok(())
}
