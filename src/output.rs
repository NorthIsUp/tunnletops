use std::collections::HashSet;
use std::fs;
use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, TryRecvError};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use owo_colors::OwoColorize;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

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

/// Streaming interactive triage. Starts immediately — findings arrive from
/// the scan pipeline in the background and are shown one at a time as they
/// come in. The user never waits for the full scan to complete.
///
/// Returns `true` if any findings remain unaddressed (kept or unreviewed) —
/// caller uses this for the process exit code.
///
/// Keys:
///   y / Enter — ignore in this file (`scope = "file"`)
///   g         — ignore globally (`scope = "global"`)
///   n         — keep the finding
///   a         — accept all queued + anything still to arrive
///   q / Esc   — save accepted rules and quit
///   ?         — toggle help footer
///   Ctrl-C    — quit (same as q)
pub fn fix_interactive(
    receiver: Receiver<FileOutcome>,
    ignorelist_path: &str,
) -> Result<bool> {
    let mut ignorelist = Ignorelist::load_or_empty(ignorelist_path)
        .with_context(|| format!("loading {}", ignorelist_path))?;

    let mut stdout = io::stdout();
    enable_raw_mode().context("enable raw mode")?;
    stdout
        .execute(EnterAlternateScreen)
        .context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("init terminal")?;

    let result = run_streaming_tui(&mut terminal, receiver, &mut ignorelist);

    // Always restore the terminal, even if the TUI returned an error.
    disable_raw_mode().ok();
    terminal
        .backend_mut()
        .execute(LeaveAlternateScreen)
        .ok();
    terminal.show_cursor().ok();

    let outcome = result?;
    save_if_added(&ignorelist, ignorelist_path, outcome.added)?;

    if outcome.queue_len == 0 {
        eprintln!(
            "no findings · scanned {} files, skipped {}",
            outcome.files_scanned, outcome.files_skipped
        );
    } else {
        eprintln!(
            "ignored {}, kept {}, {} not reviewed · scanned {} files, skipped {}",
            outcome.added,
            outcome.kept,
            outcome.unreviewed,
            outcome.files_scanned,
            outcome.files_skipped
        );
    }
    Ok(outcome.kept > 0 || outcome.unreviewed > 0)
}

struct StreamOutcome {
    added: usize,
    kept: usize,
    unreviewed: usize,
    queue_len: usize,
    files_scanned: usize,
    files_skipped: usize,
}

fn run_streaming_tui(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    receiver: Receiver<FileOutcome>,
    ignorelist: &mut Ignorelist,
) -> Result<StreamOutcome> {
    let mut queue: Vec<Finding> = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut idx = 0usize;
    let mut added = 0usize;
    let mut kept = 0usize;
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;
    let mut scan_done = false;
    let mut show_help = false;
    let mut accept_rest = false;
    let mut quit = false;

    loop {
        // Drain any findings that have arrived (non-blocking).
        loop {
            match receiver.try_recv() {
                Ok(outcome) => {
                    if outcome.skipped {
                        files_skipped += 1;
                        continue;
                    }
                    files_scanned += 1;
                    for f in outcome.findings {
                        let key = (f.file.clone(), f.entity_type.clone(), f.text.clone());
                        if !seen.insert(key) {
                            continue;
                        }
                        if accept_rest {
                            ignorelist.append(file_scope_entry(&f));
                            added += 1;
                        } else {
                            queue.push(f);
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    scan_done = true;
                    break;
                }
            }
        }

        // Exit when scan is done and either accepting-rest or queue fully reviewed.
        if scan_done && (accept_rest || idx >= queue.len()) {
            break;
        }
        if quit {
            break;
        }

        let state = RenderState {
            current: queue.get(idx),
            idx,
            queue_len: queue.len(),
            added,
            kept,
            files_scanned,
            files_skipped,
            scan_done,
            accept_rest,
            show_help,
        };
        terminal.draw(|frame| render_state(frame, &state))?;

        // Poll briefly so we can keep draining the channel while waiting for keys.
        if !event::poll(Duration::from_millis(120))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            quit = true;
            continue;
        }
        match key.code {
            KeyCode::Char('?') => show_help = !show_help,
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => quit = true,
            KeyCode::Char('a') | KeyCode::Char('A') => {
                for rem in &queue[idx..] {
                    ignorelist.append(file_scope_entry(rem));
                    added += 1;
                }
                idx = queue.len();
                accept_rest = true;
            }
            _ if idx >= queue.len() => {
                // No current finding — most keys do nothing while waiting for scan.
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                ignorelist.append(file_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                ignorelist.append(global_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                kept += 1;
                idx += 1;
            }
            _ => {}
        }
    }

    Ok(StreamOutcome {
        added,
        kept,
        unreviewed: queue.len().saturating_sub(idx),
        queue_len: queue.len(),
        files_scanned,
        files_skipped,
    })
}

struct RenderState<'a> {
    current: Option<&'a Finding>,
    idx: usize,
    queue_len: usize,
    added: usize,
    kept: usize,
    files_scanned: usize,
    files_skipped: usize,
    scan_done: bool,
    accept_rest: bool,
    show_help: bool,
}

fn render_state(frame: &mut Frame, s: &RenderState) {
    // Pack everything to the top of the screen so the action hints sit
    // directly under the finding instead of floating at the bottom.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(7), // body (box + up to 4 content lines)
            Constraint::Length(3), // footer
            Constraint::Min(0),    // empty filler below
        ])
        .split(frame.area());

    render_header(frame, chunks[0], s);
    if let Some(f) = s.current {
        render_body(frame, chunks[1], f);
    } else {
        render_waiting(frame, chunks[1], s);
    }
    render_footer(frame, chunks[2], s);
}

fn render_header(frame: &mut Frame, area: ratatui::layout::Rect, s: &RenderState) {
    let progress = if s.queue_len == 0 {
        "0/0".to_string()
    } else {
        format!("{}/{}", (s.idx + 1).min(s.queue_len), s.queue_len)
    };
    let scan_state = if s.scan_done {
        "scan complete".to_string()
    } else {
        format!("scanning · {} files done", s.files_scanned + s.files_skipped)
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " tunnletops ",
            Style::default()
                .bg(Color::Magenta)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" triage "),
        Span::styled(progress, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  ·  "),
        Span::styled(scan_state, Style::default().fg(Color::DarkGray)),
    ]));
    frame.render_widget(header, area);
}

fn render_body(frame: &mut Frame, area: ratatui::layout::Rect, f: &Finding) {
    let stripped = f.line_content.trim_start();
    let indent = f.line_content.len() - stripped.len();
    let char_count = stripped.chars().count();
    let col_start = (f.col_start as usize).saturating_sub(indent).min(char_count);
    let span_len = (f.col_end.saturating_sub(f.col_start).max(1) as usize)
        .min(char_count.saturating_sub(col_start));
    let before: String = stripped.chars().take(col_start).collect();
    let matched: String = stripped.chars().skip(col_start).take(span_len).collect();
    let after: String = stripped.chars().skip(col_start + span_len).collect();

    let gutter = format!("{:>5} │ ", f.line_num);
    let pointer_pad = " ".repeat(gutter.chars().count() + col_start);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(gutter, Style::default().fg(Color::Cyan)),
            Span::raw(before),
            Span::styled(
                matched,
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
            Span::raw(after),
        ]),
        Line::from(vec![
            Span::raw(pointer_pad.clone()),
            Span::styled(
                "▲",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw(pointer_pad),
            Span::styled(
                format!("└── {} ", f.entity_type),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("(σ {:.1})", f.score),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let title = format!(" {}:{}:{} ", f.file, f.line_num, f.col_start + 1);
    let body = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(body, area);
}

fn render_waiting(frame: &mut Frame, area: ratatui::layout::Rect, s: &RenderState) {
    let message = if s.accept_rest {
        "accepting all remaining findings as they arrive…".to_string()
    } else if s.scan_done {
        "all clear — no findings to triage".to_string()
    } else {
        format!(
            "waiting for findings…  ({} files scanned, {} skipped)",
            s.files_scanned, s.files_skipped
        )
    };
    let body = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            message,
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(" tunnletops "));
    frame.render_widget(body, area);
}

fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, s: &RenderState) {
    let keys = if s.show_help {
        Line::from(vec![
            Span::raw("y "),
            Span::styled("ignore in this file  ", Style::default().fg(Color::DarkGray)),
            Span::raw("g "),
            Span::styled("ignore globally  ", Style::default().fg(Color::DarkGray)),
            Span::raw("n "),
            Span::styled("keep  ", Style::default().fg(Color::DarkGray)),
            Span::raw("a "),
            Span::styled("accept all remaining  ", Style::default().fg(Color::DarkGray)),
            Span::raw("q "),
            Span::styled("quit & save  ", Style::default().fg(Color::DarkGray)),
            Span::raw("? "),
            Span::styled("toggle help", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            key_chip("y", "ignore file", Color::Green),
            Span::raw("  "),
            key_chip("g", "lobal", Color::Green),
            Span::raw("  "),
            key_chip("n", "keep", Color::Yellow),
            Span::raw("  "),
            key_chip("a", "ll", Color::Green),
            Span::raw("  "),
            key_chip("q", "uit", Color::Red),
            Span::raw("  "),
            key_chip("?", "help", Color::DarkGray),
        ])
    };
    let stats = Line::from(vec![
        Span::styled(
            format!(" ignored {} ", s.added),
            Style::default().fg(Color::Green),
        ),
        Span::raw("·"),
        Span::styled(
            format!(" kept {} ", s.kept),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("·"),
        Span::styled(
            format!(
                " {} queued ",
                s.queue_len.saturating_sub(s.idx).saturating_sub(
                    if s.current.is_some() { 1 } else { 0 }
                )
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let footer = Paragraph::new(vec![keys, stats]).block(Block::default().borders(Borders::TOP));
    frame.render_widget(footer, area);
}

fn key_chip(key: &str, label: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!("[{}]{}", key, label),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
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
