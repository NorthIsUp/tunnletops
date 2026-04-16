//! Regex-based recognizers.
//!
//! Two tiers:
//! - **strict**: always run, always emit. Each uses a regex + validator
//!   (Luhn, octet range, mod-97, Base58Check, phonenumber library).
//! - **broad**: only runs in hybrid modes (`regex+bert`, `regex+gliner`).
//!   Broader patterns meant to trigger NER validation on their line.
//!
//! Regex patterns are lifted from Microsoft Presidio's
//! `predefined_recognizers/generic` at commit 06616b33d.

use regex::Regex;

use crate::finding::{compute_line_starts, resolve_position, Finding};

pub trait Recognizer: Send + Sync {
    fn entity_type(&self) -> &'static str;
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding>;
}

pub struct RecognizerSet {
    strict: Vec<Box<dyn Recognizer>>,
    broad: Vec<Box<dyn Recognizer>>,
}

impl RecognizerSet {
    pub fn default_set() -> Self {
        Self {
            strict: vec![
                Box::new(EmailRecognizer::new()),
                Box::new(CreditCardRecognizer::new()),
                Box::new(PhoneRecognizer::new()),
                Box::new(UsSsnRecognizer::new()),
                Box::new(IpV4Recognizer::new()),
                Box::new(IpV6Recognizer::new()),
                Box::new(UrlRecognizer::new()),
                Box::new(MacRecognizer::new()),
                Box::new(IbanRecognizer::new()),
                Box::new(CryptoRecognizer::new()),
            ],
            broad: vec![
                Box::new(DriverLicenseCandidateRecognizer::new()),
                Box::new(PassportCandidateRecognizer::new()),
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

// =============================================================================
// Helpers
// =============================================================================

/// Generic regex → Finding converter for recognizers with no validator.
fn regex_emit(file: &str, text: &str, re: &Regex, entity_type: &str, score: f32) -> Vec<Finding> {
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

// =============================================================================
// EMAIL_ADDRESS — Presidio's RFC-closer regex
// =============================================================================

pub struct EmailRecognizer {
    re: Regex,
}

impl EmailRecognizer {
    pub fn new() -> Self {
        // Presidio "Email (Medium)" pattern — accepts full RFC local-part chars.
        Self {
            re: Regex::new(
                r"\b(?:[!#$%&'*+\-/=?^_`{|}~\w]|[!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~.\w]{0,}[!#$%&'*+\-/=?^_`{|}~\w])@\w+(?:[-.]\w+)*\.\w+(?:[-.]\w+)*\b",
            )
            .unwrap(),
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
            let raw = m.as_str();
            // Reject if the TLD is purely numeric (like `@1.8.1` in a GitHub
            // Actions pin `supercharge/redis-github-action@1.8.1`). Real TLDs
            // must contain a letter per RFC 1035.
            if let Some((_local, domain)) = raw.rsplit_once('@') {
                if let Some(tld) = domain.rsplit('.').next() {
                    if !tld.chars().any(|c| c.is_ascii_alphabetic()) {
                        continue;
                    }
                }
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

// =============================================================================
// CREDIT_CARD — Presidio's brand-prefix regex + Luhn + entropy
// =============================================================================

pub struct CreditCardRecognizer {
    re: Regex,
}

impl CreditCardRecognizer {
    pub fn new() -> Self {
        // Presidio "All Credit Cards (weak)": brand prefixes for Visa, MC,
        // Amex, Diners, Discover. Negative lookahead on `1\d{12}` in the
        // original used Python's look-behind; we drop it (Rust's `regex` crate
        // doesn't support look-around). Luhn+entropy are already our real gate.
        Self {
            re: Regex::new(
                r"\b(?:4\d{3}|5[0-5]\d{2}|6\d{3}|1\d{3}|3\d{3})[- ]?\d{3,4}[- ]?\d{3,4}[- ]?\d{3,5}\b",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for CreditCardRecognizer {
    fn entity_type(&self) -> &'static str {
        "CREDIT_CARD"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            // Reject if embedded in a float / identifier run. A CC preceded
            // by `.` is almost certainly digits pulled out of something like
            // `6.349667550340612` that happens to pass Luhn by coincidence.
            let prev = m.start().checked_sub(1).map(|i| bytes[i]);
            let next = bytes.get(m.end()).copied();
            let is_extension = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_alphanumeric() || c == b'.' || c == b'_');
            if is_extension(prev) || is_extension(next) {
                continue;
            }

            let raw = m.as_str();
            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 13 || digits.len() > 19 {
                continue;
            }
            if !has_card_entropy(&digits) || !luhn_valid(&digits) {
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

// =============================================================================
// PHONE_NUMBER — regex-for-candidates + phonenumber crate for validation
// =============================================================================

pub struct PhoneRecognizer {
    // Candidate regex — intentionally permissive. phonenumber::parse does the
    // real validation (country codes, area codes, length rules).
    re: Regex,
    regions: Vec<phonenumber::country::Id>,
}

impl PhoneRecognizer {
    pub fn new() -> Self {
        use phonenumber::country::Id;
        Self {
            re: Regex::new(r"\+?\d{1,3}?[-. ]?\(?\d{2,4}\)?[-. ]?\d{3,4}[-. ]?\d{3,5}").unwrap(),
            // Presidio's defaults minus the "FE" typo; FR added.
            regions: vec![
                Id::US,
                Id::GB,
                Id::DE,
                Id::FR,
                Id::IL,
                Id::IN,
                Id::CA,
                Id::BR,
            ],
        }
    }
}

impl Recognizer for PhoneRecognizer {
    fn entity_type(&self) -> &'static str {
        // Umbrella type for the recognizer; actual findings emit either
        // US_PHONE (country code 1) or INTL_PHONE. Disabling `PHONE_NUMBER`
        // in `[entities]` skips this recognizer entirely; disabling just
        // `US_PHONE` or `INTL_PHONE` filters at the finding level.
        "PHONE_NUMBER"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            // Skip if the match is embedded in a longer alphanumeric run or
            // in a digit/separator continuation. Phones don't appear inside
            // identifiers (`23c432562433694d34…`), credit-card digit groups,
            // or URL query strings (`foo=4325624336…`).
            let prev = m.start().checked_sub(1).map(|i| bytes[i]);
            let next = bytes.get(m.end()).copied();
            let is_word_or_sep = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_');
            if is_word_or_sep(prev) || is_word_or_sep(next) {
                continue;
            }

            let raw = m.as_str().trim();
            let digit_count = raw.chars().filter(|c| c.is_ascii_digit()).count();
            if !(10..=15).contains(&digit_count) {
                continue;
            }
            // Reject floating-point / long-ID shapes: phones never have a
            // digit group larger than 5 once you factor in separators.
            // `75.3128264600394` (sleep latency seconds) has a 13-digit group
            // and would otherwise pass phonenumber::parse.
            if !has_phone_shape(raw) {
                continue;
            }
            // Plain-digit phones (no separators) need context to disambiguate
            // from generic numeric IDs like `getPatientByExternalId("1234567890")`.
            let has_separator = raw.chars().any(|c| !c.is_ascii_digit() && c != '+');
            if !has_separator {
                let (_, _, _, line_content) =
                    resolve_position(text, &line_starts, m.start(), m.end());
                if !phone_context_mentioned(&line_content) {
                    continue;
                }
            }
            // NANP structural check: US/Canada phones must have area-code and
            // exchange first digits in 2-9. `1234567890` and `1234567891` fail
            // this — phonenumber::is_valid is sometimes too lenient on these.
            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            let national = if digits.len() == 11 && digits.starts_with('1') {
                &digits[1..]
            } else if digits.len() == 10 {
                digits.as_str()
            } else {
                ""
            };
            if national.len() == 10 {
                let bytes = national.as_bytes();
                let area_first = bytes[0];
                let exch_first = bytes[3];
                if !(b'2'..=b'9').contains(&area_first) || !(b'2'..=b'9').contains(&exch_first) {
                    continue;
                }
            }
            // Reject if the match is an IPv4 shape (4 dotted segments, each
            // 1-3 digits). `3.214.229.114` would otherwise pass phonenumber
            // as `(321)422-9114`.
            if is_ipv4_shape(raw) {
                continue;
            }
            let parsed = self
                .regions
                .iter()
                .find_map(|r| phonenumber::parse(Some(*r), raw).ok())
                .filter(phonenumber::is_valid);
            let Some(num) = parsed else {
                continue;
            };
            // Country code 1 = US/Canada NANP; everything else is INTL.
            let entity_type = if num.code().value() == 1 {
                "US_PHONE"
            } else {
                "INTL_PHONE"
            };
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            out.push(Finding {
                file: file.to_string(),
                line_num,
                col_start,
                col_end,
                entity_type: entity_type.to_string(),
                text: m.as_str().to_string(),
                score: 1.0,
                line_content,
            });
        }
        out
    }
}

/// Return `true` if the string matches a strict IPv4 shape: four
/// dot-separated segments, each 1-3 digits. Used to disambiguate phone
/// candidates that happen to have 4 dotted groups.
fn is_ipv4_shape(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

/// Loose check for phone-context keywords on the finding's line
/// (case-insensitive). Only used to gate plain-digit matches — formatted
/// numbers like `(555) 123-4567` skip this check.
fn phone_context_mentioned(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    for needle in [
        "phone",
        "tel:",
        "telephone",
        "cell",
        "cellphone",
        "mobile",
        "call ",
        "fax",
        "contact",
        "whatsapp",
        "sms",
    ] {
        if lower.contains(needle) {
            return true;
        }
    }
    false
}

/// Scan a phone-candidate match for digit groups split by separators.
/// Real phone numbers cap individual groups at 5 digits (US subscriber block,
/// or long international subscriber sections). Floating-point literals like
/// `75.3128264600394` have a trailing group of 13+ digits — easy to reject.
/// Pure-digit runs (including `+CC` prefix) are allowed and left to
/// `phonenumber::parse`.
fn has_phone_shape(raw: &str) -> bool {
    // `+` is a country-code marker, not a group separator — `+16025550123`
    // is a single unbroken digit group.
    let body = raw.strip_prefix('+').unwrap_or(raw);
    let mut current = 0usize;
    let mut max_group = 0usize;
    let mut has_separator = false;
    for ch in body.chars() {
        if ch.is_ascii_digit() {
            current += 1;
        } else if matches!(ch, '-' | '.' | ' ' | '(' | ')') {
            has_separator = true;
            if current > max_group {
                max_group = current;
            }
            current = 0;
        }
        // other chars are ignored (regex shouldn't match them anyway)
    }
    if current > max_group {
        max_group = current;
    }
    if !has_separator {
        return true;
    }
    max_group <= 5
}

// =============================================================================
// US_SSN — Presidio's validated regex (rejects 000/666/9xx area numbers)
// =============================================================================

pub struct UsSsnRecognizer {
    re: Regex,
}

impl UsSsnRecognizer {
    pub fn new() -> Self {
        // One regex covers both formats; the analyze step decides which are
        // strict enough to emit alone vs which require context.
        //   Dashed:   NNN-NN-NNNN (always emitted)
        //   Compact:  NNNNNNNNN   (only emitted with an SSN context word)
        Self {
            re: Regex::new(r"\b(?:[0-8]\d{2}|7(?:[0-6]\d|7[012]))(?:-\d{2}-\d{4}|\d{2}\d{4})\b")
                .unwrap(),
        }
    }
}

impl Recognizer for UsSsnRecognizer {
    fn entity_type(&self) -> &'static str {
        "US_SSN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        // Presidio-style area-number blacklist applied post-match. For the
        // compact (un-dashed) form, also require an SSN-context keyword on
        // the same line to avoid flagging 9-digit IDs like `"sample_id": 123456789`.
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let raw = m.as_str();
            let area: String = raw
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .take(3)
                .collect();
            if area == "000" || area == "666" || area.starts_with('9') {
                continue;
            }
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            if !raw.contains('-') && !ssn_context_mentioned(&line_content) {
                continue;
            }
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

/// Loose check for SSN context keywords on the finding's line (case-insensitive).
/// Keep this conservative — false positives here re-admit the compact-format
/// false positives we're trying to reject.
fn ssn_context_mentioned(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    for needle in [
        "ssn",
        "social security",
        "social_security",
        "socialsecurity",
        "ss#",
        "ss num",
        "tax id",
        "taxpayer id",
    ] {
        if lower.contains(needle) {
            return true;
        }
    }
    false
}

// =============================================================================
// IP_ADDRESS — Presidio's octet-validated IPv4 + IPv6 variants
// =============================================================================

pub struct IpV4Recognizer {
    re: Regex,
    /// Line-context invalidators: if the finding's line matches any of these,
    /// drop the finding. Catches IPv4 shapes embedded in SVG path data
    /// (`d="M1.5.75.75..."`) and version strings.
    line_invalidators: Vec<Regex>,
    /// Match-text invalidators: if the matched text itself matches, drop.
    /// Built-in list of reserved / loopback / unspecified / broadcast ranges.
    match_invalidators: Vec<Regex>,
}

impl IpV4Recognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(
                r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/(?:[0-2]?\d|3[0-2]))?\b",
            )
            .unwrap(),
            line_invalidators: vec![
                // SVG markup on the same line — path data is full of floats.
                Regex::new(r#"<svg|<path|viewBox|d=["']?[Mm]|fill-rule|stroke-width"#).unwrap(),
                // Hardcoded version strings like `1.2.3.4` used as semver-ish
                // markers often live after `version`, `v=`, etc.
                Regex::new(r"(?i)\bversion\s*[:=]").unwrap(),
            ],
            match_invalidators: vec![
                // Loopback (127.0.0.0/8)
                Regex::new(r"^127\.").unwrap(),
                // Unspecified / "any" address
                Regex::new(r"^0\.0\.0\.0").unwrap(),
                // Broadcast
                Regex::new(r"^255\.255\.255\.255").unwrap(),
                // Link-local (169.254.0.0/16)
                Regex::new(r"^169\.254\.").unwrap(),
                // Documentation ranges from RFC 5737
                Regex::new(r"^192\.0\.2\.").unwrap(),
                Regex::new(r"^198\.51\.100\.").unwrap(),
                Regex::new(r"^203\.0\.113\.").unwrap(),
            ],
        }
    }
}

impl Recognizer for IpV4Recognizer {
    fn entity_type(&self) -> &'static str {
        "IP_ADDRESS"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            // Reject if embedded in a longer dotted identifier like an OID
            // `1.2.543.1.34.1.34.134`. Check for `<digit>.` immediately
            // before the match, or `.<digit>` immediately after.
            let has_prior_dotted = m.start() >= 2
                && bytes[m.start() - 1] == b'.'
                && bytes[m.start() - 2].is_ascii_digit();
            let has_trailing_dotted = bytes.get(m.end()) == Some(&b'.')
                && bytes.get(m.end() + 1).is_some_and(|c| c.is_ascii_digit());
            if has_prior_dotted || has_trailing_dotted {
                continue;
            }
            if self
                .match_invalidators
                .iter()
                .any(|re| re.is_match(m.as_str()))
            {
                continue;
            }
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            if self
                .line_invalidators
                .iter()
                .any(|re| re.is_match(&line_content))
            {
                continue;
            }
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

pub struct IpV6Recognizer {
    re: Regex,
}

impl IpV6Recognizer {
    pub fn new() -> Self {
        // Combined alternation of Presidio's IPv6 + IPv4-mapped + IPv4-embedded.
        // Rust's regex crate doesn't support look-around, so we drop the
        // lookbehinds; the outer `(?:^|[^\w:])`/`(?:[^\w:]|$)` anchors keep us
        // from matching inside larger identifiers.
        Self {
            // Alternatives ordered longest-first because Rust's regex crate
            // takes the leftmost alternative that matches (PCRE-style), not
            // the longest match (POSIX-style). Putting `::` shorthand
            // alternatives with a trailing group FIRST ensures we catch
            // `2001:db8::1` fully and not as `2001:db8::`.
            re: Regex::new(
                r"(?:^|[^\w:])((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|::(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|::[0-9A-Fa-f]{1,4})",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for IpV6Recognizer {
    fn entity_type(&self) -> &'static str {
        "IP_ADDRESS"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        // Use capture group 1 (the actual IPv6) since the outer pattern has
        // a non-word character to anchor us on the left. For the right side,
        // we post-filter: reject if the byte after the match is a word char
        // (hex continues: `::e` in `::endgroup`) or another `:`.
        let line_starts = compute_line_starts(text);
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for caps in self.re.captures_iter(text) {
            let Some(m) = caps.get(1) else {
                continue;
            };
            if let Some(&next) = bytes.get(m.end()) {
                if next == b':' || next.is_ascii_alphanumeric() || next == b'_' {
                    continue;
                }
            }
            let matched = m.as_str();
            // Localhost / unspecified / documentation IPv6 built-ins.
            if matches!(
                matched,
                "::1" | "::" | "0:0:0:0:0:0:0:1" | "0:0:0:0:0:0:0:0"
            ) {
                continue;
            }
            // Documentation range 2001:db8::/32 (RFC 3849)
            if matched.starts_with("2001:db8:") || matched.starts_with("2001:DB8:") {
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
                text: m.as_str().to_string(),
                score: 1.0,
                line_content,
            });
        }
        out
    }
}

// =============================================================================
// URL — Presidio's URL pattern
// =============================================================================

pub struct UrlRecognizer {
    re: Regex,
}

impl UrlRecognizer {
    pub fn new() -> Self {
        // A simplified combined URL pattern covering schema'd and bare URLs.
        Self {
            re: Regex::new(
                r#"(?i)\b(?:https?://)?(?:[a-z0-9\-]+\.)+[a-z]{2,63}(?::\d+)?(?:/[^\s\)\]\}'"<>]*)?"#,
            )
            .unwrap(),
        }
    }
}

impl Recognizer for UrlRecognizer {
    fn entity_type(&self) -> &'static str {
        "URL"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        // A URL containing `@` before the domain is actually an email; skip.
        let emails_re = Regex::new(r"\S+@\S+").unwrap();
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let raw = m.as_str();
            if raw.contains('@') {
                continue;
            }
            // Require either a scheme or a path/port to reduce noise on bare
            // domains like `foo.py` (which would otherwise match).
            if !raw.starts_with("http") && !raw.contains('/') && !raw.contains(':') {
                continue;
            }
            // Skip if the whole match looks like a file path like `foo.py`
            // (no scheme, no /, short TLD, purely letters).
            if !raw.starts_with("http") && emails_re.is_match(raw) {
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
                score: 0.6,
                line_content,
            });
        }
        out
    }
}

// =============================================================================
// MAC_ADDRESS — Presidio's colon/hyphen + Cisco dot variants
// =============================================================================

pub struct MacRecognizer {
    colon_or_hyphen: Regex,
    cisco_dot: Regex,
}

impl MacRecognizer {
    pub fn new() -> Self {
        Self {
            // `\1` back-reference isn't supported — accept either mixed.
            colon_or_hyphen: Regex::new(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b").unwrap(),
            cisco_dot: Regex::new(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b").unwrap(),
        }
    }
}

impl Recognizer for MacRecognizer {
    fn entity_type(&self) -> &'static str {
        "MAC_ADDRESS"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let mut out = regex_emit(file, text, &self.colon_or_hyphen, self.entity_type(), 1.0);
        out.extend(regex_emit(
            file,
            text,
            &self.cisco_dot,
            self.entity_type(),
            1.0,
        ));
        out
    }
}

// =============================================================================
// IBAN_CODE — Presidio's regex + mod-97 checksum
// =============================================================================

pub struct IbanRecognizer {
    re: Regex,
}

impl IbanRecognizer {
    pub fn new() -> Self {
        // 2 letters country + 2 digits check + 11-30 alphanumeric. Presidio
        // uses country-specific length tables; we use a permissive shape and
        // rely on mod-97 to filter.
        Self {
            re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
        }
    }
}

impl Recognizer for IbanRecognizer {
    fn entity_type(&self) -> &'static str {
        "IBAN_CODE"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let raw = m.as_str();
            if !iban_mod97_valid(raw) {
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

/// IBAN mod-97 validator per ISO 13616.
/// Move the first 4 chars to the end, convert letters to 2-digit numbers
/// (A=10..Z=35), then check the big integer modulo 97 == 1.
fn iban_mod97_valid(raw: &str) -> bool {
    let rotated: String = raw[4..].chars().chain(raw[..4].chars()).collect();
    let mut remainder: u32 = 0;
    for ch in rotated.chars() {
        let val: u32 = if ch.is_ascii_digit() {
            ch.to_digit(10).unwrap()
        } else if ch.is_ascii_alphabetic() {
            (ch.to_ascii_uppercase() as u32) - ('A' as u32) + 10
        } else {
            return false;
        };
        // Process digits one or two at a time to avoid overflow (max 35 -> 2 digits).
        let digits = if val >= 10 { 2 } else { 1 };
        for i in (0..digits).rev() {
            let d = (val / 10u32.pow(i)) % 10;
            remainder = (remainder * 10 + d) % 97;
        }
    }
    remainder == 1
}

// =============================================================================
// CRYPTO — Presidio's BTC regex + Base58Check validation
// =============================================================================

pub struct CryptoRecognizer {
    re: Regex,
}

impl CryptoRecognizer {
    pub fn new() -> Self {
        // Presidio: `(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}`
        // Note: `bc1` (bech32) has its own encoding; we only validate the
        // Base58Check legacy `1…`/`3…` addresses.
        Self {
            re: Regex::new(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b").unwrap(),
        }
    }
}

impl Recognizer for CryptoRecognizer {
    fn entity_type(&self) -> &'static str {
        "CRYPTO"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let line_starts = compute_line_starts(text);
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let raw = m.as_str();
            // Skip bech32 for now; accept and mark Base58Check for 1…/3… only.
            let valid = if raw.starts_with("bc1") {
                // Bech32 validation is non-trivial (SHA-256 → checksum polymod);
                // until we add it we accept the pattern as-is with lower score.
                true
            } else {
                base58check_valid(raw)
            };
            if !valid {
                continue;
            }
            let score = if raw.starts_with("bc1") { 0.5 } else { 1.0 };
            let (line_num, col_start, col_end, line_content) =
                resolve_position(text, &line_starts, m.start(), m.end());
            out.push(Finding {
                file: file.to_string(),
                line_num,
                col_start,
                col_end,
                entity_type: self.entity_type().to_string(),
                text: raw.to_string(),
                score,
                line_content,
            });
        }
        out
    }
}

/// Base58Check validator for legacy Bitcoin addresses (P2PKH/P2SH).
/// Decodes base58, checks the last 4 bytes equal sha256(sha256(payload)).
fn base58check_valid(addr: &str) -> bool {
    use sha2::{Digest, Sha256};
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = Vec::with_capacity(addr.len());
    for ch in addr.chars() {
        let idx = match ALPHABET.iter().position(|&c| c == ch as u8) {
            Some(i) => i as u8,
            None => return false,
        };
        let mut carry: u32 = idx as u32;
        for b in num.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Account for leading '1's = leading zero bytes.
    for ch in addr.chars() {
        if ch == '1' {
            num.push(0);
        } else {
            break;
        }
    }
    num.reverse();
    if num.len() < 5 {
        return false;
    }
    let (payload, checksum) = num.split_at(num.len() - 4);
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    &hash2[..4] == checksum
}

// =============================================================================
// Broad candidate recognizers (hybrid mode only)
// =============================================================================

pub struct DriverLicenseCandidateRecognizer {
    re: Regex,
}

impl DriverLicenseCandidateRecognizer {
    pub fn new() -> Self {
        // Letter-prefixed US DL shapes only. Pure-numeric state formats
        // collide with dates/timestamps/IDs too often to be useful triggers.
        Self {
            re: Regex::new(r"\b[A-Z]{1,3}\d{6,15}\b").unwrap(),
        }
    }
}

impl Recognizer for DriverLicenseCandidateRecognizer {
    fn entity_type(&self) -> &'static str {
        "US_DRIVER_LICENSE"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 0.5)
    }
}

pub struct PassportCandidateRecognizer {
    re: Regex,
}

impl PassportCandidateRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").unwrap(),
        }
    }
}

impl Recognizer for PassportCandidateRecognizer {
    fn entity_type(&self) -> &'static str {
        "US_PASSPORT"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 0.5)
    }
}
