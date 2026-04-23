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
        Box::new(SquareOAuthRecognizer::new()),
        Box::new(MailgunKeyRecognizer::new()),
        Box::new(MailchimpKeyRecognizer::new()),
        Box::new(DiscordBotTokenRecognizer::new()),
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
        // detect-secrets AWSKeyDetector: 4-char prefix starting with A + 16
        // uppercase/digit. Prefix list from AWS's IAM identifiers doc plus
        // the extras detect-secrets tests for:
        //   AKIA = user access key        ASIA = STS session key
        //   AIDA = IAM user               AROA = IAM role
        //   AGPA = IAM group              AIPA = EC2 instance profile
        //   ACCA = context-specific cred  ABIA = legacy long-term STS
        //   A3T0 = historical / other     ANPA = managed policy
        //   ANVA = managed policy version
        Self {
            re: Regex::new(
                r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ACCA|ABIA|A3T0|ANPA|ANVA)[0-9A-Z]{16}\b",
            )
            .unwrap(),
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
        // detect-secrets TwilioKeyDetector: `(?:AC|SK)[a-z0-9]{32}`. Looser
        // than real hex — covers Twilio's internal encoding plus the
        // placeholder SIDs that appear in configs/tests. Account SIDs (AC)
        // aren't secret on their own, but SK (API key SID) is — we emit
        // both and let the user ignore ACs if they don't care.
        Self {
            re: Regex::new(r"\b(?:AC|SK)[a-z0-9]{32}\b").unwrap(),
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
// SECRET_SQUARE_OAUTH — `sq0csp-` + 43 base64url/backslash
// =============================================================================

pub struct SquareOAuthRecognizer {
    re: Regex,
}

impl SquareOAuthRecognizer {
    pub fn new() -> Self {
        // detect-secrets SquareOAuthDetector: `sq0csp-[0-9A-Za-z\\\-_]{43}`.
        // Production OAuth Application Secret (detect-secrets distinguishes
        // this from the `EAAA…` access tokens).
        Self {
            re: Regex::new(r"\bsq0csp-[0-9A-Za-z\\\-_]{43}\b").unwrap(),
        }
    }
}

impl Recognizer for SquareOAuthRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_SQUARE_OAUTH"
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
// SECRET_DISCORD_BOT_TOKEN — `[MNO]<id>.<timestamp>.<hmac>`
// =============================================================================

pub struct DiscordBotTokenRecognizer {
    re: Regex,
}

impl DiscordBotTokenRecognizer {
    pub fn new() -> Self {
        // detect-secrets DiscordBotTokenDetector:
        //   `[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}`
        // First segment is the base64-encoded user ID (starts with M/N/O
        // because Discord IDs map to that range); second is the token
        // generation timestamp; third is the HMAC.
        Self {
            re: Regex::new(
                r"[MNO][a-zA-Z\d_\-]{23,25}\.[a-zA-Z\d_\-]{6}\.[a-zA-Z\d_\-]{27}",
            )
            .unwrap(),
        }
    }
}

impl Recognizer for DiscordBotTokenRecognizer {
    fn entity_type(&self) -> &'static str {
        "SECRET_DISCORD_BOT_TOKEN"
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
        // PyPI upload tokens start with `pypi-` followed by a base64-encoded
        // macaroon whose first segment identifies the issuing index:
        //   AgEIcHlwaS5vcmc...       → pypi.org      (production)
        //   AgENdGVzdC5weXBpLm9yZw.. → test.pypi.org (staging)
        Self {
            re: Regex::new(
                r"\bpypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_\-]{80,}\b",
            )
            .unwrap(),
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
    //! Fixtures are lifted from detect-secrets's `tests/plugins/*.py` so this
    //! test suite tracks their published corpus. Real-looking token literals
    //! are split with `concat!()` so the on-disk form doesn't trip push-
    //! protection scanners on the exact shapes we're detecting — runtime
    //! values are identical.
    use super::*;

    fn texts(f: Vec<Finding>) -> Vec<String> {
        f.into_iter().map(|x| x.text).collect()
    }

    // ---------- AwsAccessKeyRecognizer — detect-secrets aws_key_test.py ----

    #[test]
    fn aws_accepts_all_prefixes() {
        let r = AwsAccessKeyRecognizer::new();
        for prefix in ["AKIA", "A3T0", "ABIA", "ACCA", "ASIA"] {
            let key = format!("{}ZZZZZZZZZZZZZZZZ", prefix);
            assert_eq!(
                texts(r.analyze("f", &key)),
                vec![key.clone()],
                "prefix {}",
                prefix
            );
        }
    }

    #[test]
    fn aws_rejects_lowercase_and_short() {
        let r = AwsAccessKeyRecognizer::new();
        assert!(r.analyze("f", "akiazzzzzzzzzzzzzzzz").is_empty());
        assert!(r.analyze("f", "AKIAZZZ").is_empty());
    }

    // ---------- GithubTokenRecognizer — detect-secrets github_token_test.py

    #[test]
    fn github_token_matches_ghp_prefix() {
        let r = GithubTokenRecognizer::new();
        let s = concat!("gh", "p_", "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn github_token_rejects_wrong_prefix() {
        let r = GithubTokenRecognizer::new();
        assert!(r
            .analyze("f", "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx")
            .is_empty());
        assert!(r.analyze("f", "foo").is_empty());
    }

    // ---------- SlackTokenRecognizer — detect-secrets slack_test.py -------

    #[test]
    fn slack_token_matches_all_variants() {
        let r = SlackTokenRecognizer::new();
        let tail = "523423-234243-234233-e039d02840a0b9379c";
        for prefix in ["xoxp", "xoxo", "xoxs", "xoxr"] {
            let s = format!("{}-{}", prefix, tail);
            assert_eq!(texts(r.analyze("f", &s)), vec![s.clone()], "prefix {}", prefix);
        }
        // xoxb with shorter tail (from detect-secrets)
        let s = concat!("xo", "xb-", "34532454-e039d02840a0b9379c");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    // ---------- StripeKeyRecognizer — detect-secrets stripe_key_test.py ---

    #[test]
    fn stripe_matches_secret_and_restricted_live() {
        let r = StripeKeyRecognizer::new();
        let sk = concat!("sk_", "live_", "ReTllpYQYfIZu2Jnf2lAPFjD");
        let rk = concat!("rk_", "live_", "5TcWfjKmJgpql9hjpRnwRXbT");
        assert_eq!(texts(r.analyze("f", sk)), vec![sk]);
        assert_eq!(texts(r.analyze("f", rk)), vec![rk]);
    }

    #[test]
    fn stripe_rejects_publishable_and_incomplete() {
        let r = StripeKeyRecognizer::new();
        assert!(r
            .analyze("f", concat!("pk_", "live_", "j5krY8XTgIcDaHDb3YrsAfCl"))
            .is_empty());
        assert!(r.analyze("f", "sk_live_").is_empty());
    }

    // ---------- GoogleApiKeyRecognizer (detect-secrets has no test file;
    //           shape lifted from Google's docs) -----------------------------

    #[test]
    fn google_api_key_shape() {
        let r = GoogleApiKeyRecognizer::new();
        let s = concat!("AIza", "SyA-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    // ---------- JwtRecognizer — detect-secrets jwt_test.py ----------------

    #[test]
    fn jwt_accepts_real_three_segment_token() {
        let r = JwtRecognizer::new();
        let s = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn jwt_rejects_non_jwt_shapes() {
        let r = JwtRecognizer::new();
        // Only one segment (detect-secrets also rejects this).
        assert!(r
            .analyze("f", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
            .is_empty());
        // Bare "jwt" literal.
        assert!(r.analyze("f", "jwt").is_empty());
        // Two segments only — missing the signature separator.
        assert!(r.analyze("f", "eyJAAAA.eyJBBB").is_empty());
    }

    // ---------- PrivateKeyRecognizer — detect-secrets private_key_test.py -

    #[test]
    fn private_key_pem_begin_variants() {
        let r = PrivateKeyRecognizer::new();
        // detect-secrets positive fixture: RSA PRIVATE KEY block.
        let s = "-----BEGIN RSA PRIVATE KEY-----\nsuper secret private key here\n\
                 -----END RSA PRIVATE KEY-----";
        assert_eq!(r.analyze("f", s).len(), 1);
        // detect-secrets positive fixture: generic PRIVATE KEY block.
        let s = "some text here\n-----BEGIN PRIVATE KEY-----\nyabba dabba doo";
        assert_eq!(r.analyze("f", s).len(), 1);
        // Additional variants we support.
        assert_eq!(r.analyze("f", "-----BEGIN OPENSSH PRIVATE KEY-----").len(), 1);
    }

    #[test]
    fn private_key_rejects_public_key() {
        let r = PrivateKeyRecognizer::new();
        assert!(r.analyze("f", "-----BEGIN PUBLIC KEY-----").is_empty());
    }

    // ---------- NpmTokenRecognizer — shape from npm's published docs ------
    //
    // detect-secrets's NPM detector matches .npmrc lines specifically; ours
    // matches the token body wherever it appears, so we use a token-shape
    // fixture here.

    #[test]
    fn npm_token_shape() {
        let r = NpmTokenRecognizer::new();
        let s = concat!("npm_", "abcdefghijklmnopqrstuvwxyz0123456789AB");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    // ---------- TwilioKeyRecognizer — detect-secrets twilio_test.py -------

    #[test]
    fn twilio_accepts_sk_and_ac_prefixes() {
        let r = TwilioKeyRecognizer::new();
        let sk = concat!("S", "K", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        let ac = concat!("A", "C", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(texts(r.analyze("f", sk)), vec![sk]);
        assert_eq!(texts(r.analyze("f", ac)), vec![ac]);
    }

    // ---------- SendGridKeyRecognizer — detect-secrets sendgrid_test.py ---

    #[test]
    fn sendgrid_accepts_real_shape() {
        let r = SendGridKeyRecognizer::new();
        let s = concat!(
            "SG", ".",
            "ngeVfQFYQlKU0ufo8x5d1A", ".",
            "TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"
        );
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
    }

    #[test]
    fn sendgrid_rejects_bad_shapes() {
        let r = SendGridKeyRecognizer::new();
        // Wrong prefix (AG instead of SG).
        assert!(r
            .analyze(
                "f",
                concat!(
                    "AG.",
                    "ngeVfQFYQlKU0ufo8x5d1A.",
                    "TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"
                )
            )
            .is_empty());
        // Missing middle segment (double dot).
        assert!(r
            .analyze(
                "f",
                concat!(
                    "SG.",
                    "ngeVfQFYQlKU0ufo8x5d1A..",
                    "TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"
                )
            )
            .is_empty());
        assert!(r.analyze("f", "foo").is_empty());
    }

    // ---------- SquareOAuthRecognizer — detect-secrets square_oauth_test.py

    #[test]
    fn square_oauth_matches_sq0csp_secret() {
        let r = SquareOAuthRecognizer::new();
        // detect-secrets positive fixture (backslash is literal, not an escape).
        let s = concat!("sq", "0csp-", "ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\abcd");
        let out = r.analyze("f", s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, s);
    }

    // ---------- MailchimpKeyRecognizer — detect-secrets mailchimp_key_test.py

    #[test]
    fn mailchimp_accepts_hex_plus_dc() {
        let r = MailchimpKeyRecognizer::new();
        // Split the hex body from the `-us<N>` datacenter tag so the on-disk
        // form isn't a single API-key-shaped literal.
        for (hex, dc) in [
            ("343ea45721923ed956e2b38c31db76aa", "-us30"),
            ("a2937653ed38c31a43ea46e2b19257db", "-us2"),
        ] {
            let s = format!("{}{}", hex, dc);
            assert_eq!(texts(r.analyze("f", &s)), vec![s.clone()]);
        }
    }

    #[test]
    fn mailchimp_rejects_bad_shapes() {
        let r = MailchimpKeyRecognizer::new();
        // Insufficient hex length.
        assert!(r
            .analyze("f", &format!("{}{}", "3ea4572956e2b381923ed34c31db76aa", "-2"))
            .is_empty());
        // Invalid region code.
        assert!(r
            .analyze("f", &format!("{}{}", "aea462953eb192d38c31a433e76257db", "-al32"))
            .is_empty());
        // Uppercase in hex segment.
        assert!(r
            .analyze("f", &format!("{}{}", "9276a43e2951aa46e2b1c33ED38357DB", "-us2"))
            .is_empty());
    }

    // ---------- DiscordBotTokenRecognizer — detect-secrets discord_test.py

    #[test]
    fn discord_bot_token_matches_real_shapes() {
        let r = DiscordBotTokenRecognizer::new();
        // Spread the distinctive `M/N/O` prefix across two string literals so
        // the on-disk form isn't a single token.
        let s = concat!("M", "Tk4NjIyNDgzNDcxOTI1MjQ4", ".", "Cl2FMQ", ".",
                        "ZnCjm1XVW7vRze4b7Cq4se7kKWs");
        assert_eq!(texts(r.analyze("f", s)), vec![s]);
        let s2 = concat!("N", "zk5MjgxNDk0NDc2NDU1OTg3", ".", "YABS5g", ".",
                         "2lmzECVlZv3vv6miVnUaKPQi2wI");
        assert_eq!(texts(r.analyze("f", s2)), vec![s2]);
    }

    #[test]
    fn discord_bot_token_rejects_wrong_prefix() {
        let r = DiscordBotTokenRecognizer::new();
        // Prefix `P` not in `[MNO]`.
        let s = concat!("P", "Z1yGvKTjE0rY0cV8i47CjAa", ".", "uRHQPq", ".",
                        "Xb1Mk2nEhe-4iUcrGOuegj57zMC");
        assert!(r.analyze("f", s).is_empty());
    }

    // ---------- PyPiTokenRecognizer — detect-secrets pypi_token_test.py --

    #[test]
    fn pypi_token_accepts_production_and_test_indices() {
        let r = PyPiTokenRecognizer::new();
        // Production-index token (pypi.org).
        let prod = concat!(
            "pypi-",
            "AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRkLTM0MjNiNmEwNWIzYgACF",
            "1sxLFsibWluaW1hbC1wcm9qZWN0Il1dAAIsWzIsWyJjYWY4OTAwZi0xNDMwLTRiYQstYm",
            "FmMi1mMDE3OGIyNWZhNTkiXV0AAAYgh2UINPjWBDwT0r3tQ1o5oZyswcjN0-IluP6z34SX3KM"
        );
        assert_eq!(r.analyze("f", prod).len(), 1);
        // Staging-index token (test.pypi.org).
        let test = concat!(
            "pypi-",
            "AgENdGVzdC5weXBpLm9yZwIkN2YxOWZhOWEtY2FjYS00MGZhLTj2MGEtODFjMnE2MjdmMzY0A",
            "AIqWzMsImJlM2FiOWI5LTRmYUTnNEg4ZS04Mjk0LWFlY2Y2NWYzNGYzNyJdAAAGIMb5Hb8nVv",
            "hcAizcVVzA-bKKnwN7Pe0RmgPRCvrPwyJf"
        );
        assert_eq!(r.analyze("f", test).len(), 1);
    }

    #[test]
    fn pypi_token_rejects_truncated_macaroon() {
        let r = PyPiTokenRecognizer::new();
        // 80-char minimum on the payload; this one is well below.
        let short = concat!("pypi-", "AgEIcHlwaS5vcmcCJDU3OTM1MjliLW");
        assert!(r.analyze("f", short).is_empty());
    }
}
