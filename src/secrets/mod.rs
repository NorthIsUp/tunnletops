//! Secret scanners adapted from Yelp's `detect-secrets` plugin set.
//!
//! Two tiers:
//! - **high_precision**: prefix/structure-anchored token detectors (AWS,
//!   GitHub, Slack, Stripe, Google, JWT, private keys, …). Low false-positive
//!   rate, enabled by default alongside the PII recognizers.
//! - **low_precision**: entropy + keyword heuristics. Noisy; must be opted
//!   into per-entity-type in `[entities]`.
//!
//! Patterns are lifted from detect-secrets's `plugins/` directory (Apache 2.0,
//! compatible with our MIT license).

use crate::finding::{compute_line_starts, resolve_position, Finding};
use crate::recognizer::Recognizer;
use regex::Regex;

pub mod high_precision;
pub mod low_precision;

/// Builders used by `RecognizerSet::default_set()`.
pub fn high_precision_recognizers() -> Vec<Box<dyn Recognizer>> {
    high_precision::all()
}

pub fn low_precision_recognizers() -> Vec<Box<dyn Recognizer>> {
    low_precision::all()
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Plain regex → Finding emitter. Useful for detectors where the regex alone
/// is the validator (most high-precision token shapes).
pub(crate) fn regex_emit(
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

/// Capture-group variant of `regex_emit` — emits finding text for the given
/// capture group index instead of the whole match. Used when the pattern
/// includes anchoring context (e.g. a preceding `=` or a quote) that we don't
/// want in the finding text itself.
pub(crate) fn regex_emit_group(
    file: &str,
    text: &str,
    re: &Regex,
    group: usize,
    entity_type: &str,
    score: f32,
) -> Vec<Finding> {
    let line_starts = compute_line_starts(text);
    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let Some(m) = caps.get(group) else { continue };
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

/// Shannon entropy (base 2) of the character distribution. detect-secrets
/// uses this on candidate secret bodies — high entropy = more likely a key,
/// low entropy = probably an identifier or placeholder.
pub(crate) fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, u32>::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f32;
    let mut h = 0.0f32;
    for &n in counts.values() {
        let p = n as f32 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_is_zero_for_constant_string() {
        assert!((shannon_entropy("aaaa") - 0.0).abs() < 1e-6);
    }

    #[test]
    fn shannon_entropy_is_high_for_random_string() {
        // A realistic AWS secret key body should sit well above 4 bits/char.
        let key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(shannon_entropy(key) > 4.0);
    }

    #[test]
    fn shannon_entropy_is_low_for_placeholder() {
        // Common placeholders in example configs.
        assert!(shannon_entropy("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") < 1.0);
        assert!(shannon_entropy("0000000000000000") < 1.0);
    }
}
