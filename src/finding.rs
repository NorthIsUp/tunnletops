use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    pub line_num: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub entity_type: String,
    pub text: String,
    pub score: f32,
    pub line_content: String,
}

#[derive(Debug, Clone)]
pub struct FileOutcome {
    pub file: String,
    pub findings: Vec<Finding>,
    pub skipped: bool,
}

impl FileOutcome {
    pub fn scanned(file: String, findings: Vec<Finding>) -> Self {
        Self {
            file,
            findings,
            skipped: false,
        }
    }

    pub fn skipped(file: String) -> Self {
        Self {
            file,
            findings: Vec::new(),
            skipped: true,
        }
    }
}

/// Resolve a byte offset in `text` to (line_num_1based, col_start_0based, line_content).
/// `line_starts` is a precomputed Vec of the byte offsets where each line begins.
pub fn resolve_position(
    text: &str,
    line_starts: &[usize],
    byte_start: usize,
    byte_end: usize,
) -> (u32, u32, u32, String) {
    let line_idx = match line_starts.binary_search(&byte_start) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    let line_start = line_starts[line_idx];
    let line_end = line_starts.get(line_idx + 1).copied().unwrap_or(text.len());
    let line_content = text[line_start..line_end]
        .trim_end_matches('\n')
        .to_string();
    let col_start = (byte_start - line_start) as u32;
    let col_end = (byte_end.saturating_sub(line_start)) as u32;
    ((line_idx + 1) as u32, col_start, col_end, line_content)
}

pub fn compute_line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, ch) in text.char_indices() {
        if ch == '\n' {
            starts.push(i + 1);
        }
    }
    starts
}
