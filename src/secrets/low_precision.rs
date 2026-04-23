//! Low-precision secret recognizers — entropy + keyword heuristics.
//!
//! These detectors flame false positives on any codebase with binary blobs,
//! hashes, UUIDs, or test fixtures. They're useful but noisy, so they're
//! gated behind explicit opt-in in `[entities]`:
//!
//! ```toml
//! [entities]
//! SECRET_HEX_HIGH_ENTROPY    = true
//! SECRET_BASE64_HIGH_ENTROPY = true
//! SECRET_KEYWORD_ASSIGNMENT  = true
//! ```
//!
//! Patterns derived from detect-secrets `plugins/high_entropy_strings.py`
//! and `plugins/keyword.py` (Apache 2.0).

use regex::Regex;

use super::{regex_emit_group, shannon_entropy};
use crate::finding::{compute_line_starts, resolve_position, Finding};
use crate::recognizer::Recognizer;

pub fn all() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(HexHighEntropyRecognizer::new()),
        Box::new(Base64HighEntropyRecognizer::new()),
        Box::new(KeywordAssignmentRecognizer::new()),
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

// =============================================================================
// SECRET_KEYWORD_ASSIGNMENT — `password = "..."`, `api_key: "..."` shapes
// =============================================================================

pub struct KeywordAssignmentRecognizer {
    re: Regex,
}

impl KeywordAssignmentRecognizer {
    pub fn new() -> Self {
        // detect-secrets KeywordDetector. Match `<keyword> = "<value>"` where
        // keyword is password/secret/api_key/access_token/…. Captures the
        // *value* (group 2) as the finding text.
        //
        // Value rules: 4+ chars, not a pure placeholder. We filter placeholders
        // in analyze(), since they're easier to enumerate than to regex-away.
        let re = Regex::new(
            r#"(?i)\b(?:passwd|password|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|bearer)\s*[:=]\s*["']([^"'\s]{4,})["']"#,
        )
        .unwrap();
        Self { re }
    }
}

impl Recognizer for KeywordAssignmentRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_KEYWORD_ASSIGNMENT"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let raw = regex_emit_group(file, text, &self.re, 1, self.entity_type(), 0.4);
        raw.into_iter()
            .filter(|f| !is_placeholder(&f.text))
            .collect()
    }
}

/// Return true if the value looks like a placeholder (no real secret).
/// detect-secrets keeps a curated deny-list; we check the common cases.
fn is_placeholder(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    // Common placeholder shapes.
    if v.chars().all(|c| c == 'x' || c == 'X')
        || v.chars().all(|c| c == '*')
        || v.chars().all(|c| c == '0')
    {
        return true;
    }
    for needle in [
        "changeme",
        "example",
        "placeholder",
        "your_",
        "yourpassword",
        "password",
        "dummy",
        "redacted",
        "<secret>",
        "<password>",
        "todo",
        "none",
        "null",
    ] {
        if lower.contains(needle) {
            return true;
        }
    }
    // Template interpolation tokens — `${env.SECRET}`, `{{VAR}}`, `%(x)s`.
    if v.contains("${") || v.contains("{{") || v.contains("%(") {
        return true;
    }
    false
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

    // ---------- KeywordAssignmentRecognizer ----------

    #[test]
    fn keyword_assignment_matches_password_literal() {
        let r = KeywordAssignmentRecognizer::new();
        let s = r#"password = "hunter2real""#;
        let f = r.analyze("f", s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].text, "hunter2real");
    }

    #[test]
    fn keyword_assignment_rejects_placeholders() {
        let r = KeywordAssignmentRecognizer::new();
        assert!(r.analyze("f", r#"password = "changeme""#).is_empty());
        assert!(r.analyze("f", r#"api_key = "xxxxxxxx""#).is_empty());
        assert!(r.analyze("f", r#"secret = "${VAULT_KEY}""#).is_empty());
        assert!(r.analyze("f", r#"password = "YOUR_PASSWORD""#).is_empty());
    }

    #[test]
    fn keyword_assignment_is_case_insensitive() {
        let r = KeywordAssignmentRecognizer::new();
        assert_eq!(r.analyze("f", r#"API_KEY: "Hk7d2ZpQ""#).len(), 1);
        assert_eq!(r.analyze("f", r#"Bearer: "abcXYZ123""#).len(), 1);
    }

    // ---------- is_placeholder ----------

    #[test]
    fn placeholder_detects_common_cases() {
        assert!(is_placeholder("xxxx"));
        assert!(is_placeholder("XXXXXX"));
        assert!(is_placeholder("CHANGEME123"));
        assert!(is_placeholder("example-password"));
        assert!(is_placeholder("${SECRET}"));
        assert!(is_placeholder("{{KEY}}"));
        assert!(!is_placeholder("real-random-value-1234"));
    }
}
