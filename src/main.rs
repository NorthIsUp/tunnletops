mod finding;
mod ignorelist;
mod migrate;
mod ner;
mod output;
mod recognizer;
mod walker;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossbeam_channel::{bounded, Receiver};
use rayon::prelude::*;

use crate::finding::{FileOutcome, Finding};
use crate::ignorelist::Ignorelist;
use crate::ner::{Model, NerEngine};
use crate::output::Formatter;
use crate::recognizer::RecognizerSet;
use crate::walker::discover_files;
use std::collections::HashSet;

const DEFAULT_IGNORELIST: &str = ".baselines/phi.toml";

#[derive(Parser)]
#[command(name = "tunnletops", version, about = "Fast PHI/PII scanner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Scan only files changed in the PR (vs merge-base of origin/master)
    #[arg(long)]
    pr: bool,

    /// Interactively triage findings and update the ignorelist
    #[arg(long)]
    fix: bool,

    /// Auto-ignore all findings (no prompts)
    #[arg(long = "fix-accept-all")]
    fix_accept_all: bool,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Tui)]
    format: Format,

    /// NER backend. `regex` disables ML inference entirely (fastest).
    #[arg(long, value_enum, default_value_t = Model::Bert)]
    model: Model,

    /// Only log files with findings (suppress clean file output)
    #[arg(long = "only-issues")]
    only_issues: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Paths to scan (default: .)
    paths: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Convert a legacy phi.yaml ignorelist to tunnletops TOML format.
    Migrate {
        #[arg(default_value = ".baselines/phi.yaml")]
        input: PathBuf,
        #[arg(default_value = ".baselines/phi.toml")]
        output: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Tui,
    Plain,
    Github,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.debug);

    if let Some(Command::Migrate { input, output }) = cli.command {
        return migrate::migrate(&input, &output);
    }

    let ignorelist = Ignorelist::load_or_empty(DEFAULT_IGNORELIST)?;
    let recognizers = RecognizerSet::default_set();
    let ner = NerEngine::load(cli.model.ner_kind()).context("loading NER model")?;

    let paths = discover_files(&cli.paths, cli.pr)?;
    tracing::debug!("discovery: {} files", paths.len());

    let (results, receiver) = start_pipeline(paths, recognizers, ner, ignorelist, cli.model);
    let formatter = Formatter::new(cli.format, cli.only_issues);
    let all_findings = stream_and_collect(receiver, &formatter)?;

    formatter.emit_summary(&all_findings)?;

    if cli.fix_accept_all {
        output::fix_accept_all(&all_findings, DEFAULT_IGNORELIST)?;
    } else if cli.fix {
        // TODO: interactive TUI fix mode (after core).
        eprintln!("--fix mode not yet implemented; use --fix-accept-all for now");
    }

    drop(results);
    let exit = if all_findings.iter().any(|f| !f.findings.is_empty()) {
        1
    } else {
        0
    };
    std::process::exit(exit);
}

fn init_logging(debug: bool) {
    let level = if debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .init();
}

struct Pipeline {
    _handle: std::thread::JoinHandle<()>,
}

fn start_pipeline(
    paths: Vec<PathBuf>,
    recognizers: RecognizerSet,
    ner: NerEngine,
    ignorelist: Ignorelist,
    model: Model,
) -> (Pipeline, Receiver<FileOutcome>) {
    let (tx, rx) = bounded::<FileOutcome>(64);
    let recognizers = Arc::new(recognizers);
    let ner = Arc::new(ner);
    let ignorelist = Arc::new(ignorelist);

    let handle = std::thread::spawn(move || {
        paths.par_iter().for_each_with(tx, |tx, path| {
            let outcome = scan_one_file(path, &recognizers, &ner, &ignorelist, model);
            let _ = tx.send(outcome);
        });
    });

    (Pipeline { _handle: handle }, rx)
}

fn scan_one_file(
    path: &std::path::Path,
    recognizers: &RecognizerSet,
    ner: &NerEngine,
    ignorelist: &Ignorelist,
    model: Model,
) -> FileOutcome {
    let file_str = path.to_string_lossy().into_owned();

    if ignorelist.is_file_skipped(&file_str) {
        return FileOutcome::skipped(file_str);
    }

    let buffer = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return FileOutcome::skipped(file_str),
    };
    if buffer.is_empty() || buffer.len() > crate::walker::MAX_FILE_SIZE {
        return FileOutcome::skipped(file_str);
    }
    let text = match std::str::from_utf8(&buffer) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(&buffer).into_owned(),
    };
    if text.trim().is_empty() {
        return FileOutcome::skipped(file_str);
    }

    // Strict regex findings: always kept.
    let mut strict: Vec<Finding> = Vec::new();
    for recognizer in recognizers.strict_iter() {
        strict.extend(recognizer.analyze(&file_str, &text));
    }

    let findings = if model.is_hybrid() {
        // Hybrid mode: broad recognizers act as line-level triggers only —
        // their findings aren't emitted. NER runs on the union of lines that
        // strict or broad recognizers flagged, and NER's findings are the
        // source of truth for PHONE/SSN/IP/etc. Strict findings are always kept.
        let mut tentative_lines: HashSet<u32> = strict.iter().map(|f| f.line_num).collect();
        for recognizer in recognizers.broad_iter() {
            for f in recognizer.analyze(&file_str, &text) {
                tentative_lines.insert(f.line_num);
            }
        }

        let ner_findings = if tentative_lines.is_empty() {
            Vec::new()
        } else {
            ner.analyze_with_filter(&file_str, &text, Some(&tentative_lines))
        };

        dedupe_findings(merge_findings(strict, Vec::new(), ner_findings))
    } else {
        // Non-hybrid: strict regex + full NER scan, deduped.
        let ner_findings = ner.analyze(&file_str, &text);
        dedupe_findings(merge_findings(strict, Vec::new(), ner_findings))
    };

    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|f| !ignorelist.is_ignored(f))
        .collect();

    FileOutcome::scanned(file_str, findings)
}

fn merge_findings(
    strict: Vec<Finding>,
    validated_tentative: Vec<Finding>,
    ner: Vec<Finding>,
) -> Vec<Finding> {
    let mut out = strict;
    out.extend(validated_tentative);
    out.extend(ner);
    out
}

/// Collapse findings that point at the same entity at the same location.
/// Keeps the one with the highest score.
fn dedupe_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        (&a.file, a.line_num, a.col_start, a.col_end, &a.entity_type)
            .cmp(&(&b.file, b.line_num, b.col_start, b.col_end, &b.entity_type))
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    findings.dedup_by(|a, b| {
        a.file == b.file
            && a.line_num == b.line_num
            && a.col_start == b.col_start
            && a.col_end == b.col_end
            && a.entity_type == b.entity_type
    });
    findings
}

fn stream_and_collect(
    rx: Receiver<FileOutcome>,
    formatter: &Formatter,
) -> Result<Vec<FileOutcome>> {
    let mut all = Vec::new();
    for outcome in rx.iter() {
        formatter.emit_file_status(&outcome);
        all.push(outcome);
    }
    Ok(all)
}
