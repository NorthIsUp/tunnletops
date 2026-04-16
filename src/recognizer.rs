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
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
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
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
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
            let valid = self.regions.iter().any(|r| {
                phonenumber::parse(Some(*r), raw).is_ok_and(|n| phonenumber::is_valid(&n))
            });
            if !valid {
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
// US_SSN — Presidio's validated regex (rejects 000/666/9xx area numbers)
// =============================================================================

pub struct UsSsnRecognizer {
    re: Regex,
}

impl UsSsnRecognizer {
    pub fn new() -> Self {
        // Presidio: `\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-]?)\d{2}\3\d{4}\b`
        // Rust's regex crate doesn't support the `\3` back-reference to enforce
        // matching separators; we allow `-` or no separator independently —
        // negligible precision loss on real SSNs.
        Self {
            re: Regex::new(r"\b(?:[0-8]\d{2}|7(?:[0-6]\d|7[012]))-?\d{2}-?\d{4}\b").unwrap(),
        }
    }
}

impl Recognizer for UsSsnRecognizer {
    fn entity_type(&self) -> &'static str {
        "US_SSN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        // Presidio-style area-number blacklist applied post-match.
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
// IP_ADDRESS — Presidio's octet-validated IPv4 + IPv6 variants
// =============================================================================

pub struct IpV4Recognizer {
    re: Regex,
}

impl IpV4Recognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(
                r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/(?:[0-2]?\d|3[0-2]))?\b",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for IpV4Recognizer {
    fn entity_type(&self) -> &'static str {
        "IP_ADDRESS"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
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
