use regex::Regex;

use crate::finding::{compute_line_starts, resolve_position, Finding};

pub trait Recognizer: Send + Sync {
    fn entity_type(&self) -> &'static str;
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding>;
}

pub struct RecognizerSet {
    /// Always run. High precision — regex + validator (Luhn, entropy).
    strict: Vec<Box<dyn Recognizer>>,
    /// Only run in hybrid modes. Broader patterns that produce candidates for
    /// NER validation. Without NER, these would be too noisy to emit.
    broad: Vec<Box<dyn Recognizer>>,
}

impl RecognizerSet {
    pub fn default_set() -> Self {
        Self {
            strict: vec![
                Box::new(EmailRecognizer::new()),
                Box::new(CreditCardRecognizer::new()),
            ],
            broad: vec![
                Box::new(PhoneCandidateRecognizer::new()),
                Box::new(SsnCandidateRecognizer::new()),
                Box::new(IpCandidateRecognizer::new()),
            ],
        }
    }

    pub fn strict_iter(&self) -> impl Iterator<Item = &dyn Recognizer> {
        self.strict.iter().map(|r| r.as_ref())
    }

    pub fn broad_iter(&self) -> impl Iterator<Item = &dyn Recognizer> {
        self.broad.iter().map(|r| r.as_ref())
    }
}

// -----------------------------------------------------------------------------
// EMAIL_ADDRESS
// -----------------------------------------------------------------------------

pub struct EmailRecognizer {
    re: Regex,
}

impl EmailRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap(),
        }
    }
}

impl Recognizer for EmailRecognizer {
    fn entity_type(&self) -> &'static str {
        "EMAIL_ADDRESS"
    }

    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            out.push(Finding {
                file: file.to_string(),
                line_num,
                col_start,
                col_end,
                entity_type: self.entity_type().to_string(),
                text: m.as_str().to_string(),
                score: 1.0,
                line_content,
            });
        }
        out
    }
}

// -----------------------------------------------------------------------------
// CREDIT_CARD (with Luhn check)
// -----------------------------------------------------------------------------

pub struct CreditCardRecognizer {
    re: Regex,
}

impl CreditCardRecognizer {
    pub fn new() -> Self {
        // Presidio's pattern: 13-19 digits, optionally separated by spaces or dashes.
        // We match the "compact" variant first; separator handling could be added later.
        Self {
            re: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
        }
    }
}

impl Recognizer for CreditCardRecognizer {
    fn entity_type(&self) -> &'static str {
        "CREDIT_CARD"
    }

    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let raw = m.as_str();
            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 13 || digits.len() > 19 {
                continue;
            }
            if !has_card_entropy(&digits) {
                continue;
            }
            if !luhn_valid(&digits) {
                continue;
            }
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            out.push(Finding {
                file: file.to_string(),
                line_num,
                col_start,
                col_end,
                entity_type: self.entity_type().to_string(),
                text: raw.to_string(),
                score: 1.0,
                line_content,
            });
        }
        out
    }
}

/// Reject runs that look like placeholder IDs (UUIDs, all-zeros, repeated digit
/// patterns). Real card numbers have at least four distinct digits.
fn has_card_entropy(digits: &str) -> bool {
    let mut seen = [false; 10];
    for ch in digits.chars() {
        if let Some(d) = ch.to_digit(10) {
            seen[d as usize] = true;
        }
    }
    seen.iter().filter(|b| **b).count() >= 4
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for ch in digits.chars().rev() {
        let mut n = match ch.to_digit(10) {
            Some(n) => n,
            None => return false,
        };
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum % 10 == 0
}

// -----------------------------------------------------------------------------
// Broad candidate recognizers (hybrid mode only)
//
// These are deliberately high-recall / low-precision: they emit anything that
// looks vaguely like PII. Hybrid mode runs NER on the surrounding lines to
// filter false positives. Without NER these would drown a real finding in
// hundreds of ID columns, port numbers, and version strings — so they do not
// appear in `RecognizerSet::strict`.
// -----------------------------------------------------------------------------

pub struct PhoneCandidateRecognizer {
    re: Regex,
}

impl PhoneCandidateRecognizer {
    pub fn new() -> Self {
        // US-ish: optional leading +1, then 3+3+4 digits with common separators.
        Self {
            re: Regex::new(r"\+?1?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b").unwrap(),
        }
    }
}

impl Recognizer for PhoneCandidateRecognizer {
    fn entity_type(&self) -> &'static str {
        "PHONE_NUMBER"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_candidates(file, text, &self.re, self.entity_type(), 0.5)
    }
}

pub struct SsnCandidateRecognizer {
    re: Regex,
}

impl SsnCandidateRecognizer {
    pub fn new() -> Self {
        // NNN-NN-NNNN or NNN NN NNNN — no checksum.
        Self {
            re: Regex::new(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b").unwrap(),
        }
    }
}

impl Recognizer for SsnCandidateRecognizer {
    fn entity_type(&self) -> &'static str {
        "US_SSN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_candidates(file, text, &self.re, self.entity_type(), 0.5)
    }
}

pub struct IpCandidateRecognizer {
    re: Regex,
}

impl IpCandidateRecognizer {
    pub fn new() -> Self {
        // IPv4 — permissive (matches version strings too; that's what NER is for).
        Self {
            re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        }
    }
}

impl Recognizer for IpCandidateRecognizer {
    fn entity_type(&self) -> &'static str {
        "IP_ADDRESS"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_candidates(file, text, &self.re, self.entity_type(), 0.5)
    }
}

fn regex_candidates(
    file: &str,
    text: &str,
    re: &Regex,
    entity_type: &str,
    score: f32,
) -> Vec<Finding> {
    let line_starts = compute_line_starts(text);
    let mut out = Vec::new();
    for m in re.find_iter(text) {
        let (line_num, col_start, col_end, line_content) =
            resolve_position(text, &line_starts, m.start(), m.end());
        out.push(Finding {
            file: file.to_string(),
            line_num,
            col_start,
            col_end,
            entity_type: entity_type.to_string(),
            text: m.as_str().to_string(),
            score,
            line_content,
        });
    }
    out
}
