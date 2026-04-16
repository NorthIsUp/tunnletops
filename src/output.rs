use std::fs;

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
    pub fn emit_file_status(&self, outcome: &FileOutcome) {
        if outcome.skipped {
            return;
        }
        if !outcome.findings.is_empty() {
            println!("{}: {} finding(s)", outcome.file, outcome.findings.len());
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
        "{}{} {}{} {}",
        g,
        "·".cyan().bold(),
        " ".repeat(mid),
        "└──".magenta().bold(),
        f.entity_type.magenta().bold()
    );
}

pub fn fix_accept_all(outcomes: &[FileOutcome], ignorelist_path: &str) -> Result<()> {
    let mut ignorelist = Ignorelist::load_or_empty(ignorelist_path)
        .with_context(|| format!("loading {}", ignorelist_path))?;
    let mut added = 0usize;
    for outcome in outcomes {
        for f in &outcome.findings {
            ignorelist.append(IgnoreEntry {
                kind: None,
                scope: Some("line".to_string()),
                file: Some(f.file.clone()),
                line: Some(f.line_num.to_string()),
                entity_type: Some(f.entity_type.clone()),
                text: Some(f.text.clone()),
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
    eprintln!("ignored {} finding(s)", added);
    Ok(())
}
