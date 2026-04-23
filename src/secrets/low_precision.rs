//! Low-precision secret recognizers — entropy heuristics.
//!
//! These detectors flame false positives on any codebase with binary blobs,
//! hashes, UUIDs, or test fixtures. They're useful but noisy, so they're
//! gated behind explicit opt-in in `[entities]`:
//!
//! ```toml
//! [entities]
//! SECRET_HEX_HIGH_ENTROPY    = true
//! SECRET_BASE64_HIGH_ENTROPY = true
//! ```
//!
//! Patterns derived from detect-secrets `plugins/high_entropy_strings.py`
//! (Apache 2.0). The keyword-assignment detector lives in `high_precision`
//! since its false-positive rate is low enough to run by default.

use regex::Regex;

use super::shannon_entropy;
use crate::finding::{compute_line_starts, resolve_position, Finding};
use crate::recognizer::Recognizer;

pub fn all() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(HexHighEntropyRecognizer::new()),
        Box::new(Base64HighEntropyRecognizer::new()),
    ]
}

// =============================================================================
// SECRET_HEX_HIGH_ENTROPY
// =============================================================================

pub struct HexHighEntropyRecognizer {
    re: Regex,
    /// Shannon-entropy floor. detect-secrets defaults to 3.0 bits/char for
    /// hex; below that we treat the value as a test hash / constant.
    threshold: f32,
}

impl HexHighEntropyRecognizer {
    pub fn new() -> Self {
        Self {
            // Quoted hex run of ≥32 chars — short hashes (MD5=32, SHA1=40,
            // SHA256=64 hex). Anchoring to quotes avoids matching identifier
            // runs and commit SHAs in markdown.
            re: Regex::new(r#"["']([0-9a-fA-F]{32,})["']"#).unwrap(),
            threshold: 3.0,
        }
    }
}

impl Recognizer for HexHighEntropyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_HEX_HIGH_ENTROPY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for caps in self.re.captures_iter(text) {
            let Some(m) = caps.get(1) else { continue };
            let body = m.as_str();
            if shannon_entropy(body) < self.threshold {
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
                text: body.to_string(),
                score: 0.5,
                line_content,
            });
        }
        out
    }
}

// =============================================================================
// SECRET_BASE64_HIGH_ENTROPY
// =============================================================================

pub struct Base64HighEntropyRecognizer {
    re: Regex,
    /// detect-secrets defaults to 4.5 bits/char for base64. Higher than hex
    /// because base64's alphabet is 64 chars — a truly random string hits
    /// ~6.0, so 4.5 filters out identifiers and padding-heavy values.
    threshold: f32,
}

impl Base64HighEntropyRecognizer {
    pub fn new() -> Self {
        Self {
            // Quoted run of ≥20 base64 chars. Intentionally excludes `=`
            // padding to stay in the character-class definition cleanly;
            // trailing `=` on the original string still yields a high-entropy
            // prefix that we catch here.
            re: Regex::new(r#"["']([A-Za-z0-9+/_\-]{20,})["']"#).unwrap(),
            threshold: 4.5,
        }
    }
}

impl Recognizer for Base64HighEntropyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_BASE64_HIGH_ENTROPY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for caps in self.re.captures_iter(text) {
            let Some(m) = caps.get(1) else { continue };
            let body = m.as_str();
            // Skip pure-hex matches — HexHighEntropyRecognizer owns those.
            if body.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if shannon_entropy(body) < self.threshold {
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
                text: body.to_string(),
                score: 0.5,
                line_content,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- HexHighEntropyRecognizer ----------
    //
    // Fixtures lifted from detect-secrets tests/plugins/high_entropy_strings_test.py.

    #[test]
    fn hex_entropy_accepts_random_hex() {
        let r = HexHighEntropyRecognizer::new();
        // detect-secrets positive fixture (32-char random hex, a.k.a. MD5 length).
        let s = r#"token: "2b00042f7481c7b056c4b410d28f33cf""#;
        assert_eq!(r.analyze("f", s).len(), 1);
    }

    #[test]
    fn hex_entropy_rejects_low_entropy_run() {
        let r = HexHighEntropyRecognizer::new();
        let s = r#"hash: "00000000000000000000000000000000""#;
        assert!(r.analyze("f", s).is_empty());
    }

    #[test]
    fn hex_entropy_rejects_short_run() {
        let r = HexHighEntropyRecognizer::new();
        // detect-secrets negative: below 32-char minimum.
        let s = r#"value: "aaaaaa""#;
        assert!(r.analyze("f", s).is_empty());
    }

    // ---------- Base64HighEntropyRecognizer ----------

    #[test]
    fn base64_entropy_accepts_random_base64() {
        let r = Base64HighEntropyRecognizer::new();
        // detect-secrets positive fixture (60-char base64).
        let s = r#"token: "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;
        assert_eq!(r.analyze("f", s).len(), 1);
    }

    #[test]
    fn base64_entropy_rejects_low_entropy_identifier() {
        let r = Base64HighEntropyRecognizer::new();
        // Repeated 2-char alphabet → entropy 1.0 bits/char, below 4.5 floor.
        let s = r#"id: "abababababababababab""#;
        assert!(r.analyze("f", s).is_empty());
    }

    #[test]
    fn base64_entropy_yields_to_hex_recognizer() {
        // A pure-hex string should not emit via the base64 recognizer — the
        // hex recognizer owns it.
        let r = Base64HighEntropyRecognizer::new();
        let s = r#"sha: "2b00042f7481c7b056c4b410d28f33cf""#;
        assert!(r.analyze("f", s).is_empty());
    }

}
