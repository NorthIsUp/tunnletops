mod finding;
mod ignorelist;
mod migrate;
mod ner;
mod output;
mod pool;
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

    /// Minimum confidence threshold for NER findings (0.0 - 1.0).
    /// Only applies to `--model bert` / `--model gliner` and their hybrids.
    /// Default is backend-specific (0.5 for GLiNER).
    #[arg(long)]
    threshold: Option<f32>,

    /// Comma-separated list of entity types to emit; everything else is
    /// dropped. E.g. `--entities EMAIL_ADDRESS,CREDIT_CARD,US_SSN`.
    #[arg(long, value_delimiter = ',')]
    entities: Vec<String>,

    /// Verbose: stream every candidate (strict/broad regex and NER) to stderr,
    /// including candidates that were filtered out. Useful for tuning hybrid
    /// modes and diagnosing misses.
    #[arg(long, short = 'v')]
    verbose: bool,

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
    /// Load and re-save the ignorelist with entries sorted deterministically
    /// (entity_type → scope → file → text/pattern). Whole-file skips go
    /// first. `[entities]` is always alphabetical.
    Format {
        #[arg(default_value = ".baselines/phi.toml")]
        path: PathBuf,
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

    match cli.command {
        Some(Command::Migrate { input, output }) => return migrate::migrate(&input, &output),
        Some(Command::Format { path }) => {
            let list = Ignorelist::load_or_empty(&path)
                .with_context(|| format!("loading {}", path.display()))?;
            list.save(&path)
                .with_context(|| format!("saving {}", path.display()))?;
            eprintln!("formatted {}", path.display());
            return Ok(());
        }
        None => {}
    }

    let ignorelist = Ignorelist::load_or_empty(DEFAULT_IGNORELIST)?;
    let recognizers = RecognizerSet::default_set();
    let ner = NerEngine::load(cli.model.ner_kind(), cli.threshold).context("loading NER model")?;

    let entity_filter: Option<std::collections::HashSet<String>> = if cli.entities.is_empty() {
        None
    } else {
        Some(cli.entities.iter().cloned().collect())
    };

    let paths = discover_files(&cli.paths, cli.pr)?;
    tracing::debug!("discovery: {} files", paths.len());

    let (results, receiver) = start_pipeline(
        paths,
        recognizers,
        ner,
        ignorelist,
        cli.model,
        cli.verbose,
        entity_filter,
    );
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
    verbose: bool,
    entity_filter: Option<std::collections::HashSet<String>>,
) -> (Pipeline, Receiver<FileOutcome>) {
    let (tx, rx) = bounded::<FileOutcome>(64);
    let recognizers = Arc::new(recognizers);
    let ner = Arc::new(ner);
    let ignorelist = Arc::new(ignorelist);
    let entity_filter = Arc::new(entity_filter);

    let handle = std::thread::spawn(move || {
        paths.par_iter().for_each_with(tx, |tx, path| {
            let outcome = scan_one_file(
                path,
                &recognizers,
                &ner,
                &ignorelist,
                model,
                verbose,
                entity_filter.as_ref().as_ref(),
            );
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
    verbose: bool,
    entity_filter: Option<&std::collections::HashSet<String>>,
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

    // Strict regex findings. Skip recognizers whose entity type is disabled
    // via `[entities] disabled = [...]` — saves regex work. Apply ignorelist
    // immediately so ignored lines don't force expensive NER work in hybrid.
    let strict: Vec<Finding> = recognizers
        .strict_iter()
        .filter(|r| !ignorelist.is_entity_disabled(r.entity_type()))
        .flat_map(|r| r.analyze(&file_str, &text))
        .filter(|f| {
            let keep = !ignorelist.is_ignored(f);
            if verbose {
                log_candidate("strict", f, if keep { "kept" } else { "ignored" });
            }
            keep
        })
        .collect();

    let findings = if model.is_hybrid() {
        // Hybrid: broad regex produces candidates; NER acts as a pure validator.
        // A broad candidate is kept only if NER reports an entity of the same
        // type that overlaps the candidate. NER-only findings (entity types NOT
        // caught by any broad regex, e.g. PERSON/ORG/LOC) are dropped — those
        // require non-hybrid `--model bert` or `--model gliner`.
        //
        // This matches the user's original intent: "broad regex finds candidates,
        // NER filters false positives".
        let broad_candidates: Vec<Finding> = recognizers
            .broad_iter()
            .filter(|r| !ignorelist.is_entity_disabled(r.entity_type()))
            .flat_map(|r| r.analyze(&file_str, &text))
            .filter(|f| {
                let keep = !ignorelist.is_ignored(f);
                if verbose && !keep {
                    log_candidate("broad", f, "ignored");
                }
                keep
            })
            .collect();

        let tentative_lines: HashSet<u32> = strict
            .iter()
            .chain(broad_candidates.iter())
            .map(|f| f.line_num)
            .collect();

        let ner_findings: Vec<Finding> = if tentative_lines.is_empty() {
            Vec::new()
        } else {
            ner.analyze_with_filter(&file_str, &text, Some(&tentative_lines))
                .into_iter()
                .filter(|f| !ignorelist.is_entity_disabled(&f.entity_type))
                .collect()
        };

        // Build a quick lookup of (line, entity_type) → NER spans to confirm against.
        let mut ner_spans_by_key: std::collections::HashMap<(u32, String), Vec<(u32, u32)>> =
            std::collections::HashMap::new();
        for n in &ner_findings {
            ner_spans_by_key
                .entry((n.line_num, n.entity_type.clone()))
                .or_default()
                .push((n.col_start, n.col_end));
        }

        let validated: Vec<Finding> = broad_candidates
            .into_iter()
            .filter_map(|c| {
                let spans = ner_spans_by_key.get(&(c.line_num, c.entity_type.clone()));
                let confirmed = spans
                    .map(|ss| {
                        ss.iter()
                            .any(|&(s, e)| spans_overlap((c.col_start, c.col_end), (s, e)))
                    })
                    .unwrap_or(false);
                if verbose {
                    log_candidate(
                        "broad",
                        &c,
                        if confirmed {
                            "ner-confirmed"
                        } else {
                            "ner-dropped"
                        },
                    );
                }
                if confirmed {
                    Some(c)
                } else {
                    None
                }
            })
            .filter(|f| !ignorelist.is_ignored(f))
            .collect();

        dedupe_findings(merge_findings(strict, validated, Vec::new()))
    } else {
        // Non-hybrid: strict regex + full NER scan. Apply ignorelist to NER
        // findings as they stream in (we can't skip NER lines here since
        // there's no regex-candidate signal to filter on).
        let ner_findings: Vec<Finding> = ner
            .analyze(&file_str, &text)
            .into_iter()
            .filter(|f| !ignorelist.is_entity_disabled(&f.entity_type))
            .filter(|f| {
                let keep = !ignorelist.is_ignored(f);
                if verbose {
                    log_candidate("ner", f, if keep { "kept" } else { "ignored" });
                }
                keep
            })
            .collect();
        dedupe_findings(merge_findings(strict, Vec::new(), ner_findings))
    };

    // Apply --entities filter last: user-requested subset, case-insensitive.
    let findings: Vec<Finding> = if let Some(filter) = entity_filter {
        findings
            .into_iter()
            .filter(|f| {
                filter
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(&f.entity_type))
            })
            .collect()
    } else {
        findings
    };

    FileOutcome::scanned(file_str, findings)
}

fn spans_overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn log_candidate(source: &str, f: &Finding, status: &str) {
    eprintln!(
        "verbose {file}:{line}:{col} {source:6} {entity:<18} score={score:.2} {status:<13} {text:?}",
        file = f.file,
        line = f.line_num,
        col = f.col_start + 1,
        source = source,
        entity = f.entity_type,
        score = f.score,
        status = status,
        text = f.text,
    );
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
