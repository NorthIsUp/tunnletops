use std::collections::{HashMap, HashSet};
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

/// Default context window shown around each finding in `tui` output format
/// and the `--fix` TUI. The fix TUI lets the user adjust this live.
const DEFAULT_CONTEXT_RADIUS: usize = 3;

fn emit_tui(findings: &[&Finding]) {
    let mut cache: HashMap<String, Vec<String>> = HashMap::new();
    for f in findings {
        render_diagnostic(f, &mut cache, DEFAULT_CONTEXT_RADIUS);
        println!();
    }
}

fn render_diagnostic(f: &Finding, cache: &mut HashMap<String, Vec<String>>, radius: usize) {
    let stripped = f.line_content.trim_start();
    let indent = f.line_content.len() - stripped.len();
    let col = f.col_start as usize - indent.min(f.col_start as usize);
    let span = (f.col_end.saturating_sub(f.col_start).max(1)) as usize;

    // Pull surrounding lines from the file so the match has context. If the
    // file can't be read we fall back to just the match line.
    let file_lines = load_file_lines(cache, &f.file);
    let line_idx = (f.line_num as usize).saturating_sub(1);
    let (start_line, lines_above, lines_below) = match file_lines {
        Some(lines) => {
            let start = line_idx.saturating_sub(radius);
            let above: Vec<&str> = lines
                .get(start..line_idx)
                .map(|s| s.iter().map(String::as_str).collect())
                .unwrap_or_default();
            let below: Vec<&str> = lines
                .get(line_idx + 1..(line_idx + 1 + radius).min(lines.len()))
                .map(|s| s.iter().map(String::as_str).collect())
                .unwrap_or_default();
            (start + 1, above, below)
        }
        None => (f.line_num as usize, Vec::new(), Vec::new()),
    };

    // Gutter width accommodates the highest line number we'll render.
    let max_num = f.line_num as usize + lines_below.len();
    let gutter_w = max_num.to_string().len();
    let pad = " ".repeat(gutter_w + 1);
    let mid = col + span / 2;

    println!(
        "{}{} {}:{}:{}",
        pad,
        "┌─".cyan().bold(),
        f.file,
        f.line_num,
        f.col_start + 1
    );

    for (i, line) in lines_above.iter().enumerate() {
        let n = start_line + i;
        let body = line.trim_start();
        println!(
            "{:>w$} {} {}",
            n,
            "│".cyan().dimmed(),
            body.dimmed(),
            w = gutter_w
        );
    }

    // Match line (highlighted).
    let before = stripped.get(..col).unwrap_or("");
    let match_slice = stripped.get(col..col + span).unwrap_or("");
    let after = stripped.get(col + span..).unwrap_or("");
    println!(
        "{:>w$} {} {}{}{}",
        f.line_num,
        "│".cyan().bold(),
        before,
        match_slice.red().bold().underline(),
        after,
        w = gutter_w
    );
    println!(
        "{}{} {}{}",
        pad,
        "·".cyan().bold(),
        " ".repeat(mid),
        "▲".magenta().bold()
    );
    println!(
        "{}{} {}{} {} {}",
        pad,
        "·".cyan().bold(),
        " ".repeat(mid),
        "└──".magenta().bold(),
        f.entity_type.magenta().bold(),
        format!("(σ {:.1})", f.score).dimmed()
    );

    for (i, line) in lines_below.iter().enumerate() {
        let n = f.line_num as usize + 1 + i;
        let body = line.trim_start();
        println!(
            "{:>w$} {} {}",
            n,
            "│".cyan().dimmed(),
            body.dimmed(),
            w = gutter_w
        );
    }
}

fn load_file_lines<'a>(
    cache: &'a mut HashMap<String, Vec<String>>,
    path: &str,
) -> Option<&'a Vec<String>> {
    if !cache.contains_key(path) {
        let text = fs::read_to_string(path).ok()?;
        let lines: Vec<String> = text.lines().map(String::from).collect();
        cache.insert(path.to_string(), lines);
    }
    cache.get(path)
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
/// Keys — all four ignore actions write an `[[ignored]]` entry and advance:
///   l           — ignore this line only       (path + line)
///   f           — ignore this file            (path)
///   d           — ignore this directory       (path = "dir/**")
///   g           — ignore globally             (no path)
///   a           — ignore all queued + everything still to arrive
///   [ / ]       — shrink / grow the context window (±N lines)
///   q / Esc / ^C — save and quit
///   h / ?       — toggle help footer
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

    let result = run_streaming_tui(&mut terminal, receiver, &mut ignorelist, ignorelist_path);

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
            "ignored {}, {} not reviewed · scanned {} files, skipped {}",
            outcome.added,
            outcome.unreviewed,
            outcome.files_scanned,
            outcome.files_skipped
        );
    }
    Ok(outcome.unreviewed > 0)
}

struct StreamOutcome {
    added: usize,
    unreviewed: usize,
    queue_len: usize,
    files_scanned: usize,
    files_skipped: usize,
}

fn run_streaming_tui(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    receiver: Receiver<FileOutcome>,
    ignorelist: &mut Ignorelist,
    ignorelist_path: &str,
) -> Result<StreamOutcome> {
    let mut queue: Vec<Finding> = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut file_cache: HashMap<String, Vec<String>> = HashMap::new();
    let mut context_radius: usize = DEFAULT_CONTEXT_RADIUS;
    let mut idx = 0usize;
    let mut added = 0usize;
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;
    let mut scan_done = false;
    let mut show_help = false;
    let mut accept_rest = false;
    let mut quit = false;
    // Custom-entry input mode: `c` opens an editable line where the user
    // types either a literal/glob (`text`) or a regex (`match`). Tab
    // toggles which kind. Enter commits → IgnoreEntry; Esc cancels.
    let mut input_open = false;
    let mut input_buf = String::new();
    let mut input_is_regex = false;

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

        // Preload context lines for the current finding so the renderer
        // doesn't need mutable access to the cache inside `draw`.
        let current = queue.get(idx);
        let (ctx_above, ctx_below, ctx_start_line) = match current {
            Some(f) => slice_context(&mut file_cache, f, context_radius),
            None => (Vec::new(), Vec::new(), 0),
        };

        let state = RenderState {
            current,
            context_above: &ctx_above,
            context_below: &ctx_below,
            context_start_line: ctx_start_line,
            context_radius,
            idx,
            queue_len: queue.len(),
            added,
            files_scanned,
            files_skipped,
            scan_done,
            accept_rest,
            show_help,
            input_open,
            input_buf: &input_buf,
            input_is_regex,
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
        // Custom-entry editor takes over the keymap until Enter or Esc.
        // Quit/scope-shortcut keys are intentionally inert here so the user
        // can type freely (incl. `q`, `f`, etc. as part of a pattern).
        if input_open {
            match key.code {
                KeyCode::Esc => {
                    input_open = false;
                    input_buf.clear();
                    input_is_regex = false;
                }
                KeyCode::Tab | KeyCode::BackTab => input_is_regex = !input_is_regex,
                KeyCode::Backspace => {
                    input_buf.pop();
                }
                KeyCode::Enter => {
                    if !input_buf.is_empty() && idx < queue.len() {
                        let f = &queue[idx];
                        let entry = if input_is_regex {
                            IgnoreEntry {
                                entity_type: Some(f.entity_type.clone()),
                                regex: Some(input_buf.clone()),
                                ..Default::default()
                            }
                        } else {
                            IgnoreEntry {
                                entity_type: Some(f.entity_type.clone()),
                                text: Some(input_buf.clone()),
                                ..Default::default()
                            }
                        };
                        ignorelist.append(entry);
                        added += 1;
                        idx += 1;
                    }
                    input_open = false;
                    input_buf.clear();
                    input_is_regex = false;
                }
                KeyCode::Char(ch) => input_buf.push(ch),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::Char('?') => {
                show_help = !show_help
            }
            KeyCode::Char('[') => context_radius = context_radius.saturating_sub(2),
            KeyCode::Char(']') => context_radius = (context_radius + 2).min(20),
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
            KeyCode::Char('l') | KeyCode::Char('L') => {
                ignorelist.append(line_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                ignorelist.append(file_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                ignorelist.append(dir_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                ignorelist.append(global_scope_entry(&queue[idx]));
                added += 1;
                idx += 1;
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                // URL-only: ignore by domain. Silently no-op for non-URL
                // findings or unparseable hosts so the user can spam `u`
                // without breaking the queue.
                if let Some(entry) = domain_scope_entry(&queue[idx]) {
                    ignorelist.append(entry);
                    added += 1;
                    idx += 1;
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                // Open the custom-entry editor on the current finding. Pre-
                // seeded with the finding's text so the user can edit a
                // literal into a glob/regex without retyping. Defaults to
                // text mode; Tab toggles to regex.
                if idx < queue.len() {
                    input_open = true;
                    input_buf = queue[idx].text.clone();
                    input_is_regex = false;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                // Reload phi.toml from disk and skip past any queued
                // findings the new ignorelist now matches. Lets the user
                // edit phi.toml in another terminal and re-check without
                // restarting the scan. Reload errors silently keep the
                // existing ignorelist (so a half-written file mid-edit
                // doesn't blow up the TUI).
                if let Ok(reloaded) = Ignorelist::load_or_empty(ignorelist_path) {
                    *ignorelist = reloaded;
                    while idx < queue.len()
                        && (ignorelist.is_file_skipped(&queue[idx].file)
                            || ignorelist.is_ignored(&queue[idx]))
                    {
                        idx += 1;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(StreamOutcome {
        added,
        unreviewed: queue.len().saturating_sub(idx),
        queue_len: queue.len(),
        files_scanned,
        files_skipped,
    })
}

struct RenderState<'a> {
    current: Option<&'a Finding>,
    /// True while the user is typing a custom matcher. The footer flips
    /// from the keymap chips to a single-line input prompt.
    input_open: bool,
    /// In-progress text for the custom-entry editor (echoed to the user).
    input_buf: &'a str,
    /// Whether the current input is a regex (`match` field) vs a literal
    /// (`text`). Tab toggles in the input loop.
    input_is_regex: bool,
    // Context lines above the match (in file order). May be shorter than
    // `context_radius` when near the top of the file.
    context_above: &'a [String],
    context_below: &'a [String],
    // 1-based line number of `context_above[0]`, or of the match when there's
    // no prior context. Used for gutter labels.
    context_start_line: u32,
    context_radius: usize,
    idx: usize,
    queue_len: usize,
    added: usize,
    files_scanned: usize,
    files_skipped: usize,
    scan_done: bool,
    accept_rest: bool,
    show_help: bool,
}

fn render_state(frame: &mut Frame, s: &RenderState) {
    // Body height grows/shrinks with the context window. Cap so we don't
    // push the footer off smaller terminals.
    let content_lines = if s.current.is_some() {
        1 + s.context_above.len() as u16 + 1 + 2 + s.context_below.len() as u16
    } else {
        3
    };
    let body_h = (content_lines + 2).min(frame.area().height.saturating_sub(5));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),      // header
            Constraint::Length(body_h), // body (dynamic)
            Constraint::Length(3),      // footer
            Constraint::Min(0),         // filler
        ])
        .split(frame.area());

    render_header(frame, chunks[0], s);
    if let Some(f) = s.current {
        render_body(frame, chunks[1], f, s);
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
            " tunneltops ",
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

fn render_body(frame: &mut Frame, area: ratatui::layout::Rect, f: &Finding, s: &RenderState) {
    let stripped = f.line_content.trim_start();
    let indent = f.line_content.len() - stripped.len();
    let char_count = stripped.chars().count();
    let col_start = (f.col_start as usize).saturating_sub(indent).min(char_count);
    let span_len = (f.col_end.saturating_sub(f.col_start).max(1) as usize)
        .min(char_count.saturating_sub(col_start));
    let before: String = stripped.chars().take(col_start).collect();
    let matched: String = stripped.chars().skip(col_start).take(span_len).collect();
    let after: String = stripped.chars().skip(col_start + span_len).collect();

    // Gutter width accommodates the highest line number we'll render.
    let max_ln = f.line_num as usize + s.context_below.len();
    let gutter_w = max_ln.to_string().len().max(3);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));

    for (i, src) in s.context_above.iter().enumerate() {
        let n = s.context_start_line as usize + i;
        let body = src.trim_start();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>w$} │ ", n, w = gutter_w),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(body.to_string(), Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled(
            format!("{:>w$} │ ", f.line_num, w = gutter_w),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(before),
        Span::styled(
            matched,
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ),
        Span::raw(after),
    ]));

    // Marker rows use a `·` "continuation dot" in the gutter (instead of
    // a line number + `│`) so the reader can tell at a glance that these
    // aren't code lines. Matches the plain-format renderer above and the
    // shape the user sketched (`. ` between code rows).
    let marker_gutter = || {
        Span::styled(
            format!("{:>w$} · ", "", w = gutter_w),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };
    let marker_offset = " ".repeat(col_start);
    lines.push(Line::from(vec![
        marker_gutter(),
        Span::raw(marker_offset.clone()),
        Span::styled(
            "▲",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        marker_gutter(),
        Span::raw(marker_offset),
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
    ]));

    for (i, src) in s.context_below.iter().enumerate() {
        let n = f.line_num as usize + 1 + i;
        let body = src.trim_start();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>w$} │ ", n, w = gutter_w),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(body.to_string(), Style::default().fg(Color::DarkGray)),
        ]));
    }

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

/// Pull up to `radius` lines before and after the finding's match line.
/// Returns (above, below, 1-based line number of `above[0]`) — line number
/// falls back to the match line number when there is no prior context.
fn slice_context(
    cache: &mut HashMap<String, Vec<String>>,
    f: &Finding,
    radius: usize,
) -> (Vec<String>, Vec<String>, u32) {
    let Some(lines) = load_file_lines(cache, &f.file) else {
        return (Vec::new(), Vec::new(), f.line_num);
    };
    let line_idx = (f.line_num as usize).saturating_sub(1);
    let start = line_idx.saturating_sub(radius);
    let above = lines
        .get(start..line_idx)
        .map(<[String]>::to_vec)
        .unwrap_or_default();
    let below = lines
        .get(line_idx + 1..(line_idx + 1 + radius).min(lines.len()))
        .map(<[String]>::to_vec)
        .unwrap_or_default();
    ((above), below, (start + 1) as u32)
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
    .block(Block::default().borders(Borders::ALL).title(" tunneltops "));
    frame.render_widget(body, area);
}

fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, s: &RenderState) {
    if s.input_open {
        let kind_label = if s.input_is_regex { "match (regex)" } else { "text (literal/glob)" };
        let prompt = Line::from(vec![
            Span::styled(
                format!(" custom [{kind_label}] "),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                s.input_buf.to_string(),
                Style::default().fg(Color::White),
            ),
            // Block cursor caret so the user can see where typing lands.
            Span::styled(
                "█",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK),
            ),
        ]);
        let hint = Line::from(vec![
            Span::styled(
                " Enter ",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled("save  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Tab ",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled("toggle text/regex  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Esc ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("cancel", Style::default().fg(Color::DarkGray)),
        ]);
        let footer = Paragraph::new(vec![prompt, hint])
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(footer, area);
        return;
    }
    let keys = if s.show_help {
        Line::from(vec![
            Span::styled("ignore ", Style::default().fg(Color::DarkGray)),
            Span::raw("l "),
            Span::styled("line  ", Style::default().fg(Color::DarkGray)),
            Span::raw("f "),
            Span::styled("file  ", Style::default().fg(Color::DarkGray)),
            Span::raw("d "),
            Span::styled("directory  ", Style::default().fg(Color::DarkGray)),
            Span::raw("g "),
            Span::styled("globally  ", Style::default().fg(Color::DarkGray)),
            Span::raw("u "),
            Span::styled("domain — *.host of URL finding (URL only)  ", Style::default().fg(Color::DarkGray)),
            Span::raw("c "),
            Span::styled("custom text/regex — Tab toggles, Enter saves, Esc cancels  ", Style::default().fg(Color::DarkGray)),
            Span::raw("r "),
            Span::styled("reload phi.toml from disk + re-filter queue   ·  ", Style::default().fg(Color::DarkGray)),
            Span::raw("a "),
            Span::styled("all remaining   ·  ", Style::default().fg(Color::DarkGray)),
            Span::raw("[ ] "),
            Span::styled(
                format!("context ±{}   ·  ", s.context_radius),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw("q/Esc/^C "),
            Span::styled("quit & save  ", Style::default().fg(Color::DarkGray)),
            Span::raw("h "),
            Span::styled("toggle help", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        let mut spans = vec![
            Span::styled(
                "ignore ",
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            ),
            key_chip("l", "ine", Color::Green),
            Span::raw("  "),
            key_chip("f", "ile", Color::Green),
            Span::raw("  "),
            key_chip("d", "ir", Color::Green),
            Span::raw("  "),
            key_chip("g", "lobal", Color::Green),
        ];
        if s.current.map(|f| f.entity_type == "URL").unwrap_or(false) {
            spans.push(Span::raw("  "));
            spans.push(key_chip("u", "domain (url)", Color::Cyan));
        }
        spans.push(Span::raw("  "));
        spans.push(key_chip("c", "ustom", Color::Cyan));
        spans.push(Span::raw("  "));
        spans.push(key_chip("r", "eload", Color::Magenta));
        spans.extend([
            Span::styled("   ·   ", Style::default().fg(Color::DarkGray)),
            key_chip("a", "ll", Color::Yellow),
            Span::styled(
                format!("   [ ] ±{}   ", s.context_radius),
                Style::default().fg(Color::DarkGray),
            ),
            key_chip("q", "uit", Color::Red),
            Span::raw("  "),
            key_chip("h", "elp", Color::DarkGray),
        ]);
        Line::from(spans)
    };
    let stats = Line::from(vec![
        Span::styled(
            format!(" ignored {} ", s.added),
            Style::default().fg(Color::Green),
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

fn line_scope_entry(f: &Finding) -> IgnoreEntry {
    // `path` + `line` → line scope (inferred on load).
    IgnoreEntry {
        entity_type: Some(f.entity_type.clone()),
        path: Some(f.file.clone()),
        line: Some(f.line_num.to_string()),
        text: Some(f.text.clone()),
        ..Default::default()
    }
}

fn file_scope_entry(f: &Finding) -> IgnoreEntry {
    // `path` present → file scope (inferred on load).
    IgnoreEntry {
        entity_type: Some(f.entity_type.clone()),
        path: Some(f.file.clone()),
        text: Some(f.text.clone()),
        ..Default::default()
    }
}

fn dir_scope_entry(f: &Finding) -> IgnoreEntry {
    // File-scope with a `dir/**` glob — ignores `text` anywhere under the
    // finding's parent directory. Findings at the repo root (no parent)
    // fall back to a plain `**` (whole-tree) glob.
    let parent = std::path::Path::new(&f.file)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty());
    let glob = match parent {
        Some(p) => format!("{}/**", p),
        None => "**".to_string(),
    };
    IgnoreEntry {
        entity_type: Some(f.entity_type.clone()),
        path: Some(glob),
        text: Some(f.text.clone()),
        ..Default::default()
    }
}

fn global_scope_entry(f: &Finding) -> IgnoreEntry {
    // `path` absent → global scope (inferred on load).
    IgnoreEntry {
        entity_type: Some(f.entity_type.clone()),
        text: Some(f.text.clone()),
        ..Default::default()
    }
}

/// Global URL-domain ignore entry: `text = "*.<host>"` so a single rule
/// covers the host and every subdomain — the typical "I trust this vendor
/// entirely" flow. Returns None if the finding isn't a URL or its host
/// can't be parsed (key handler should no-op in that case).
fn domain_scope_entry(f: &Finding) -> Option<IgnoreEntry> {
    if f.entity_type != "URL" {
        return None;
    }
    let host = crate::ignorelist::extract_url_host(&f.text)?;
    Some(IgnoreEntry {
        entity_type: Some("URL".to_string()),
        text: Some(format!("*.{host}")),
        ..Default::default()
    })
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
            // File-scoped (path present, no line) so the ignore survives when
            // the line shifts from edits above it. Matches any occurrence of
            // `(entity_type, text)` in this file. Dedupe so we don't write
            // the same entry once per occurrence.
            let key = (f.file.clone(), f.entity_type.clone(), f.text.clone());
            if !seen.insert(key) {
                continue;
            }
            ignorelist.append(file_scope_entry(f));
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
