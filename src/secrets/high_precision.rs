//! High-precision secret recognizers — prefix/structure-anchored token shapes.
//!
//! Each detector here has a distinctive prefix (e.g. `AKIA`, `ghp_`, `xoxb-`)
//! or a deterministic structural shape (JWT three-segment base64url,
//! `-----BEGIN ... PRIVATE KEY-----`). False-positive rate is low enough to
//! run by default alongside the PII recognizers.
//!
//! Patterns lifted from detect-secrets `plugins/` (Apache 2.0).

use regex::Regex;

use super::regex_emit;
use crate::finding::Finding;
use crate::recognizer::Recognizer;

pub fn all() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(AwsAccessKeyRecognizer::new()),
        Box::new(GithubTokenRecognizer::new()),
        Box::new(SlackTokenRecognizer::new()),
        Box::new(StripeKeyRecognizer::new()),
        Box::new(GoogleApiKeyRecognizer::new()),
        Box::new(JwtRecognizer::new()),
        Box::new(PrivateKeyRecognizer::new()),
        Box::new(NpmTokenRecognizer::new()),
        Box::new(TwilioKeyRecognizer::new()),
        Box::new(SendGridKeyRecognizer::new()),
        Box::new(SquareAccessTokenRecognizer::new()),
        Box::new(MailgunKeyRecognizer::new()),
        Box::new(MailchimpKeyRecognizer::new()),
        Box::new(DiscordWebhookRecognizer::new()),
        Box::new(PyPiTokenRecognizer::new()),
    ]
}

// =============================================================================
// SECRET_AWS_ACCESS_KEY — `AKIA` / `ASIA` (session) / `AIDA` / `AGPA` / etc.
// =============================================================================

pub struct AwsAccessKeyRecognizer {
    re: Regex,
}

impl AwsAccessKeyRecognizer {
    pub fn new() -> Self {
        // detect-secrets AWSKeyDetector: 4-letter prefix + 16 uppercase/digit.
        // AKIA=user, ASIA=STS, AIDA=IAM user, AROA=role, AGPA=group,
        // ANPA/ANVA=ignored (expired pattern). We keep the common ones.
        Self {
            re: Regex::new(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA)[0-9A-Z]{16}\b").unwrap(),
        }
    }
}

impl Recognizer for AwsAccessKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_AWS_ACCESS_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_GITHUB_TOKEN — `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + classic 40-hex
// =============================================================================

pub struct GithubTokenRecognizer {
    fine_grained: Regex,
}

impl GithubTokenRecognizer {
    pub fn new() -> Self {
        // detect-secrets GitHubTokenDetector (2022+ token format).
        // `gh[pousr]_` + 36+ base62. Classic 40-hex PATs are covered by the
        // hex-entropy detector in low_precision, not here — too ambiguous
        // without a prefix.
        Self {
            fine_grained: Regex::new(r"\b(?:gh[pousr])_[A-Za-z0-9_]{36,251}\b").unwrap(),
        }
    }
}

impl Recognizer for GithubTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_GITHUB_TOKEN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.fine_grained, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_SLACK_TOKEN — `xox[abprs]-` + 10+ chars
// =============================================================================

pub struct SlackTokenRecognizer {
    re: Regex,
}

impl SlackTokenRecognizer {
    pub fn new() -> Self {
        // detect-secrets SlackDetector. Covers bot/user/app/workflow tokens.
        Self {
            re: Regex::new(r"\bxox[abprsoe]-[A-Za-z0-9\-]{10,}\b").unwrap(),
        }
    }
}

impl Recognizer for SlackTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_SLACK_TOKEN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_STRIPE_KEY — live/test secret + restricted keys
// =============================================================================

pub struct StripeKeyRecognizer {
    re: Regex,
}

impl StripeKeyRecognizer {
    pub fn new() -> Self {
        // detect-secrets StripeDetector. `sk_live_`, `rk_live_` (restricted),
        // plus test variants. pk_live_ (publishable) is intentionally out —
        // public by design, not a secret.
        Self {
            re: Regex::new(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,247}\b").unwrap(),
        }
    }
}

impl Recognizer for StripeKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_STRIPE_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_GOOGLE_API_KEY — `AIza` + 35 base64url chars
// =============================================================================

pub struct GoogleApiKeyRecognizer {
    re: Regex,
}

impl GoogleApiKeyRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\bAIza[0-9A-Za-z_\-]{35}\b").unwrap(),
        }
    }
}

impl Recognizer for GoogleApiKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_GOOGLE_API_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_JWT — three base64url segments separated by `.`, first starts `eyJ`
// =============================================================================

pub struct JwtRecognizer {
    re: Regex,
}

impl JwtRecognizer {
    pub fn new() -> Self {
        // detect-secrets JwtTokenDetector. Header starts with `eyJ` (base64 of
        // `{"`); payload also base64url; signature is optional for `alg: none`
        // but we require all three to avoid matching arbitrary dotted identifiers.
        Self {
            re: Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b").unwrap(),
        }
    }
}

impl Recognizer for JwtRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_JWT"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_PRIVATE_KEY — PEM begin marker
// =============================================================================

pub struct PrivateKeyRecognizer {
    re: Regex,
}

impl PrivateKeyRecognizer {
    pub fn new() -> Self {
        // detect-secrets PrivateKeyDetector. Match the BEGIN marker only —
        // the full block spans many lines and our Finding model is per-line.
        // This captures RSA, DSA, EC, OpenSSH, PGP, and generic PRIVATE KEY.
        Self {
            re: Regex::new(
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for PrivateKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_PRIVATE_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_NPM_TOKEN — `npm_` + 36 base62
// =============================================================================

pub struct NpmTokenRecognizer {
    re: Regex,
}

impl NpmTokenRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(),
        }
    }
}

impl Recognizer for NpmTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_NPM_TOKEN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_TWILIO_KEY — Account SID `AC…` or API Key SID `SK…` + 32 hex
// =============================================================================

pub struct TwilioKeyRecognizer {
    re: Regex,
}

impl TwilioKeyRecognizer {
    pub fn new() -> Self {
        // detect-secrets TwilioKeyDetector. Account SIDs aren't secret on
        // their own, but SK (API key SID) is — we emit both and let the
        // user ignore ACs if they don't care.
        Self {
            re: Regex::new(r"\b(?:AC|SK)[0-9a-f]{32}\b").unwrap(),
        }
    }
}

impl Recognizer for TwilioKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_TWILIO_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_SENDGRID_KEY — `SG.` + 22 base64url + `.` + 43 base64url
// =============================================================================

pub struct SendGridKeyRecognizer {
    re: Regex,
}

impl SendGridKeyRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b").unwrap(),
        }
    }
}

impl Recognizer for SendGridKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_SENDGRID_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_SQUARE_ACCESS_TOKEN — `EAAA` + 60 base64url
// =============================================================================

pub struct SquareAccessTokenRecognizer {
    re: Regex,
}

impl SquareAccessTokenRecognizer {
    pub fn new() -> Self {
        // detect-secrets SquareOAuthDetector.
        Self {
            re: Regex::new(r"\bEAAA[A-Za-z0-9_\-]{60}\b").unwrap(),
        }
    }
}

impl Recognizer for SquareAccessTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_SQUARE_ACCESS_TOKEN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_MAILGUN_KEY — `key-` + 32 hex
// =============================================================================

pub struct MailgunKeyRecognizer {
    re: Regex,
}

impl MailgunKeyRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\bkey-[0-9a-f]{32}\b").unwrap(),
        }
    }
}

impl Recognizer for MailgunKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_MAILGUN_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_MAILCHIMP_KEY — 32 hex + `-us` + 1-2 digits
// =============================================================================

pub struct MailchimpKeyRecognizer {
    re: Regex,
}

impl MailchimpKeyRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\b[0-9a-f]{32}-us\d{1,2}\b").unwrap(),
        }
    }
}

impl Recognizer for MailchimpKeyRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_MAILCHIMP_KEY"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_DISCORD_WEBHOOK — discord.com/api/webhooks/<id>/<token>
// =============================================================================

pub struct DiscordWebhookRecognizer {
    re: Regex,
}

impl DiscordWebhookRecognizer {
    pub fn new() -> Self {
        Self {
            re: Regex::new(
                r"https://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{68}",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for DiscordWebhookRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_DISCORD_WEBHOOK"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

// =============================================================================
// SECRET_PYPI_TOKEN — `pypi-AgEIcHlwaS5vcmc…` (prefix fixed, length ~180)
// =============================================================================

pub struct PyPiTokenRecognizer {
    re: Regex,
}

impl PyPiTokenRecognizer {
    pub fn new() -> Self {
        // PyPI upload tokens all start with `pypi-AgEIcHlwaS5vcmc` (base64 of
        // "pypi.org"). 80+ base64url chars of macaroon payload.
        Self {
            re: Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{80,}\b").unwrap(),
        }
    }
}

impl Recognizer for PyPiTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_PYPI_TOKEN"
    }
    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        regex_emit(file, text, &self.re, self.entity_type(), 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(f: Vec<Finding>) -> Vec<String> {
        f.into_iter().map(|x| x.text).collect()
    }

    #[test]
    fn aws_matches_akia() {
        let r = AwsAccessKeyRecognizer::new();
        let key = concat!("A", "K", "IAIOSFODNN7EXAMPLE");
        let input = format!("aws: {} in config", key);
        assert_eq!(texts(r.analyze("f", &input)), vec![key.to_string()]);
    }

    #[test]
    fn aws_rejects_lowercase_and_short() {
        let r = AwsAccessKeyRecognizer::new();
        assert!(r.analyze("f", "akiaiosfodnn7example").is_empty());
        assert!(r.analyze("f", "AKIASHORT").is_empty());
    }

    #[test]
    fn github_token_matches_fine_grained_prefixes() {
        let r = GithubTokenRecognizer::new();
        let s = concat!("gh", "p", "_1234567890abcdefghijklmnopqrstuvwxyzABCD");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
        let s2 = concat!("gh", "s", "_1234567890abcdefghijklmnopqrstuvwxyzABCD");
        assert_eq!(texts(r.analyze("f", s2)), vec![s2]);
    }

    #[test]
    fn slack_token_matches_xoxb() {
        let r = SlackTokenRecognizer::new();
        // Split to avoid tripping secret scanners on the literal — same value
        // at runtime.
        let s = concat!("xo", "xb-", "1234567890-1234567890-abcdef1234567890abcdef");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn stripe_matches_sk_live() {
        let r = StripeKeyRecognizer::new();
        let s = concat!("sk_", "live", "_1234567890abcdefABCDEFGHIJ");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn stripe_rejects_publishable() {
        let r = StripeKeyRecognizer::new();
        assert!(r
            .analyze("f", concat!("pk_", "live", "_1234567890abcdefABCDEFGHIJ"))
            .is_empty());
    }

    #[test]
    fn google_api_key_shape() {
        let r = GoogleApiKeyRecognizer::new();
        let s = "AIzaSyA-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456";
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn jwt_three_segments() {
        let r = JwtRecognizer::new();
        let s = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123DEF_456";
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn private_key_pem_begin() {
        let r = PrivateKeyRecognizer::new();
        assert_eq!(r.analyze("f", "-----BEGIN RSA PRIVATE KEY-----\ndata").len(), 1);
        assert_eq!(r.analyze("f", "-----BEGIN OPENSSH PRIVATE KEY-----").len(), 1);
        assert_eq!(r.analyze("f", "-----BEGIN PRIVATE KEY-----").len(), 1);
    }

    #[test]
    fn private_key_rejects_public_key() {
        let r = PrivateKeyRecognizer::new();
        assert!(r.analyze("f", "-----BEGIN PUBLIC KEY-----").is_empty());
    }

    #[test]
    fn npm_token_shape() {
        let r = NpmTokenRecognizer::new();
        let s = "npm_abcdefghijklmnopqrstuvwxyz0123456789AB";
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn twilio_api_key_sid() {
        let r = TwilioKeyRecognizer::new();
        let s = concat!("S", "K", "0123456789abcdef0123456789abcdef");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn sendgrid_shape() {
        let r = SendGridKeyRecognizer::new();
        let s = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn discord_webhook_shape() {
        let r = DiscordWebhookRecognizer::new();
        let s = "https://discord.com/api/webhooks/12345678901234567890/\
                 abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012345-_";
        assert_eq!(r.analyze("f", s).len(), 1);
    }
}
