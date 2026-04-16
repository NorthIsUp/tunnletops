use regex::Regex;

use crate::finding::{compute_line_starts, resolve_position, Finding};

pub trait Recognizer: Send + Sync {
    fn entity_type(&self) -> &'static str;
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding>;
}

pub struct RecognizerSet {
    recognizers: Vec<Box<dyn Recognizer>>,
}

impl RecognizerSet {
    pub fn default_set() -> Self {
        Self {
            recognizers: vec![
                Box::new(EmailRecognizer::new()),
                Box::new(CreditCardRecognizer::new()),
            ],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Recognizer> {
        self.recognizers.iter().map(|r| r.as_ref())
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
