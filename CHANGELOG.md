# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.14] - 2026-04-16

### Added

- `IpV4Recognizer` and `IpV6Recognizer` gain invalidators — post-match
  filters that drop false positives without extending the main regex:
  - **Line-context** invalidators for IPv4: SVG path data
    (`<svg`, `<path`, `viewBox`, `d="M…"`, `fill-rule`, `stroke-width`)
    and version-string contexts (`version = ...`). Handles shapes like
    `d="M1.5.75.75 0 0 1-1.5z"` in inline SVG.
  - **Match-text** invalidators for reserved / built-in ranges:
    - IPv4: `127.0.0.0/8` loopback, `0.0.0.0` unspecified,
      `255.255.255.255` broadcast, `169.254.0.0/16` link-local,
      and RFC 5737 documentation ranges (`192.0.2.0/24`,
      `198.51.100.0/24`, `203.0.113.0/24`).
    - IPv6: `::1` loopback, `::` unspecified, full forms
      `0:0:0:0:0:0:0:{0,1}`, and RFC 3849 `2001:db8::/32`
      documentation range.

## [0.5.13] - 2026-04-16

### Fixed

- **Phone false positive on floating-point literals** like
  `"sleep_latency_seconds": 75.3128264600394`. Added a shape check:
  with separators present, no digit group may exceed 5 digits. `+CC`
  prefixes don't count as group-breaking separators (so `+16025550123`
  still matches correctly).

### Changed

- Walker now uses ripgrep's `ignore` crate instead of shelling out to
  `git ls-files`. Respects `.gitignore`, `.ignore`, `.git/info/exclude`,
  and global `core.excludesFile`. Works in non-git trees too.

## [0.5.12] - 2026-04-16

### Fixed

- **SSN false positive** on 9-digit sample IDs like `"sample_id": "123456789"`.
  The compact (un-dashed) SSN form now requires an SSN context keyword on
  the same line to emit (`ssn`, `social security`, `ss#`, `tax id`, etc.,
  case-insensitive). Traditional dashed format `NNN-NN-NNNN` still emits
  unconditionally.
- Regex now forces symmetric separators: either both dashes or neither,
  no more `12345-6789` half-dashed matches.

## [0.5.11] - 2026-04-16

### Fixed

- **IPv6 false positive** on sequences like `::e` in `echo "::endgroup::"`.
  Rust's `regex` crate doesn't support lookahead, so IpV6Recognizer now
  post-filters: reject matches where the byte after the capture is a word
  char, `:`, or `_`. `\b` alone doesn't catch this because `e` and `n`
  are both word chars.
- **Phone false positive** on digit runs embedded in identifiers like
  `23c432562433694d34cba…` (hex IDs in URL query strings). Previous
  filter only rejected when adjacent to digits/dashes/dots; now rejects
  any adjacent alphanumeric or `_` so phones must sit in whitespace /
  punctuation context.

## [0.5.10] - 2026-04-16

### Fixed

- `clippy::doc_lazy_continuation` on resolve_ignorelist_path doc comment
  (v0.5.9 CI failure).

## [0.5.9] - 2026-04-16

### Added

- `--baselines PATH` flag to explicitly point at an ignorelist. Useful
  when running tunnletops from a different working tree than the one
  that owns `.baselines/phi.toml` (e.g. running from the main repo
  while your `phi.toml` lives in a worktree).
- Legacy `phi.yaml` read-only fallback: if `.baselines/phi.toml`
  doesn't exist but `.baselines/phi.yaml` does, tunnletops reads the
  YAML. Ignore rules come through; `[entities]` section isn't
  expressible in legacy YAML so entity-disable doesn't apply.
  `--fix-accept-all` always writes TOML (friendly upgrade path).

### Resolution order

1. `--baselines PATH` (explicit)
2. `.baselines/phi.toml` in cwd
3. `.baselines/phi.yaml` in cwd (legacy, read-only)

## [0.5.8] - 2026-04-16

### Changed

- Per-file status line uses proper singular/plural: `1 finding` vs
  `2 findings` (previously always `(s)`).
- Status line now reports the count of ignorelist-suppressed matches
  when non-zero, e.g. `2 findings, 1 ignored`. Gives visibility into
  how much the ignorelist is filtering on each file.

## [0.5.7] - 2026-04-16

### Fixed

- `clippy::needless_lifetimes` on `extract_header_field` (v0.5.6 CI lint).

## [0.5.6] - 2026-04-16

### Changed

- Readability polish for saved ignorelists:
  - Each `[[ignored]]` block now starts with its identifying field —
    `type` for whole-file skips, `entity_type` for everything else.
  - Extra blank line between different entity_type groups so the
    file scans like sections at a glance.
  - `None` fields are omitted from output (no more empty lines).

## [0.5.5] - 2026-04-16

### Fixed

- Replace `sort_by` with `sort_by_key` to satisfy clippy (v0.5.4 release
  workflow failed on this lint).
- Remove stray `.baselines/phi.toml` that accidentally landed in v0.5.4.

## [0.5.4] - 2026-04-16

### Added

- `tunnletops format [PATH]` — load and re-save an ignorelist with
  deterministic ordering. Diffs become meaningful, merges easier.
  Default path: `.baselines/phi.toml`.

### Changed

- Saved ignorelists are now deterministically sorted:
  - `[entities]` — alphabetical by entity name
  - `[[ignored]]` — primary: whole-file skips first; then by
    `entity_type`; then `scope` (global → file → line); then `file`;
    then `pattern` or `text`.
- `[entities]` now serializes at the top of the file (struct field
  order: entities, then ignored).

## [0.5.3] - 2026-04-16

### Added

- `pattern` field on `[[ignored]]` entries — a regex matched against the
  finding's text. Takes precedence over `text` when both are set. Use
  TOML literal strings (single quotes) to avoid double-escaping:

  ```toml
  [[ignored]]
  entity_type = "EMAIL_ADDRESS"
  scope       = "global"
  pattern     = '@[\w.-]*\.?clarahealth\.com$'
  ```

  Regexes are compiled once at load time. Invalid patterns print a warning
  and are skipped (the rule is ignored, not the whole file).

## [0.5.2] - 2026-04-16

### Changed

- **Breaking (for the day-old `[entities]` section):** switched from
  `disabled = ["URL"]` to a flat `NAME = true|false` map. Reads nicer
  and leaves room to grow per-entity config later:
  ```toml
  [entities]
  URL = false
  MAC_ADDRESS = false
  ```
  Missing entries default to enabled. `true` is the same as not listing
  the entity at all.

## [0.5.1] - 2026-04-16

### Added

- `[entities]` section in `phi.toml` — disable specific entity types
  per-project. Recognizers whose type is disabled don't run at all;
  NER findings of disabled types are dropped.
  Example:
  ```toml
  [entities]
  disabled = ["URL", "MAC_ADDRESS"]
  ```

### Changed

- `--fix-accept-all` now writes `scope = "file"` entries instead of
  `scope = "line"`. Ignores survive when a line shifts from edits above
  it — same `(file, entity_type, text)` anywhere in the file still
  matches. Existing `scope = "line"` entries with numeric `line = "N"`
  continue to work for users who want strict line-anchored matching.
- `fix-accept-all` dedupes by `(file, entity_type, text)` so the same
  email appearing 9 times in a seed file now writes one `[[ignored]]`
  entry instead of 9 identical ones.

## [0.5.0] - 2026-04-16

### Added

- Seven new strict recognizers ported from Microsoft Presidio's
  `predefined_recognizers/generic` at commit 06616b33d:
  - `IpV4Recognizer` with octet range validation (rejects `999.999.999.999`)
  - `IpV6Recognizer` covering `::` shorthand, IPv4-mapped (`::ffff:1.2.3.4`),
    and IPv4-embedded variants
  - `UrlRecognizer` (both `http(s)://` and bare-domain forms)
  - `MacRecognizer` (colon/hyphen + Cisco-dot formats)
  - `IbanRecognizer` with ISO 13616 mod-97 checksum validation
  - `CryptoRecognizer` with Base58Check validation for legacy BTC addresses
  - `PhoneRecognizer` using the `phonenumber` crate (port of Google's
    `libphonenumber`) — regex finds candidates, library validates country
    codes, area codes, and length rules. Replaces the old regex-only broad
    recognizer.
- `US_SSN` promoted from broad to strict: Presidio's validated regex rejects
  `000/666/9xx` area numbers.
- `--threshold N.N` flag — override the NER confidence threshold (GLiNER
  default 0.5). Only affects `--model gliner` / `--model regex+gliner`.
- `--entities TYPE1,TYPE2,...` flag — filter output to a subset of entity
  types, case-insensitive. Example:
  `--entities EMAIL_ADDRESS,CREDIT_CARD,US_SSN`.
- BILOU (B-/I-/U-/L-) prefix support in the BERT BIO decoder — previously
  only B-/I-. Matches Presidio's HuggingFaceNerRecognizer behavior.

### Changed

- `EmailRecognizer` upgraded to Presidio's RFC-closer pattern (accepts
  `+`, `'`, `~`, etc. in the local part).
- `CreditCardRecognizer` tightened to brand-prefix shapes (Visa, MC, Amex,
  Diners, Discover) instead of any 13-19 digit run.
- Only `US_DRIVER_LICENSE` and `US_PASSPORT` remain broad (hybrid-only).
  All other entity types are validated by their own checksum / parser and
  emitted directly in `--model regex`.

### Notes

- `URL` findings tend to dominate output on doc-heavy repos. Filter with
  `--entities` or add `[[ignored]]` rules for known internal domains.
- The `phonenumber` crate ships with metadata for 200+ regions. Default
  matching regions: US, GB, DE, FR, IL, IN, CA, BR.

## [0.4.0] - 2026-04-15

### Added

- `--verbose` (`-v`) flag streams each candidate and filter decision to stderr
  with source tag (strict/broad/ner) and score. Use to tune hybrid modes and
  diagnose what got kept or dropped.
- Session pooling for BERT (4 sessions) and GLiNER (2 sessions) removes the
  single-Mutex bottleneck — rayon threads can now run NER concurrently.
- Batched BERT inference: 32 lines per ort forward pass with padded tensors
  instead of one call per line. Amortizes per-call overhead.
- Broad recognizers for `US_DRIVER_LICENSE` and `US_PASSPORT` so those types
  can flow through hybrid modes.

### Changed

- **Hybrid semantic now strict**: `--model regex+bert` / `--model regex+gliner`
  emit only strict regex findings + broad regex candidates that NER confirms
  (same entity type, overlapping span). NER-only findings are dropped. This
  fixes GLiNER false positives like `US_DRIVER_LICENSE` hallucinations on
  numeric IDs. For PERSON / ORGANIZATION / LOCATION detection, use the
  non-hybrid `--model bert` or `--model gliner`.
- Ignorelist applied before NER: candidates that match an ignore rule no
  longer trigger NER inference on their line.
- `DriverLicenseCandidateRecognizer` requires a 1-3 letter prefix. Pure-numeric
  state DL formats (AL/AK/CT/MS) collide with dates, timestamps, and opaque
  IDs too often to be useful triggers — users who need them can add a
  project-specific recognizer.

### Performance

Clara backend, cold scan (each run in isolation to avoid shared warm cache):

| Mode | v0.3.0 | v0.4.0 |
|---|---|---|
| `regex` | 0.55s | 0.55s |
| `regex+bert` | 1.3s | ~1.6s |
| `regex+gliner` | 3.7s | **1.4s** |

## [0.3.0] - 2026-04-15

### Added

- `--model regex+bert` and `--model regex+gliner` hybrid modes. Broad regex
  recognizers (PHONE_NUMBER, US_SSN, IP_ADDRESS) trigger NER on candidate
  lines only, skipping 99%+ of source files entirely. Dramatically faster than
  pure NER modes while still catching the NER-visible entity types.
- New broad recognizers active only in hybrid modes: `PhoneCandidateRecognizer`,
  `SsnCandidateRecognizer`, `IpCandidateRecognizer`. Deliberately high-recall /
  low-precision — NER filters the false positives.
- Finding dedupe: when the same (file, line, col, entity_type) appears from
  multiple sources (regex + NER), keep the highest-scored one.

### Changed

- `RecognizerSet` split into `strict_iter()` (always) and `broad_iter()`
  (hybrid-only). `--model regex` continues to produce only strict findings.
- `NerEngine::load` now takes `Option<NerKind>` so the model selection and the
  hybrid flag are orthogonal.

### Performance

Clara backend (thousands of files) cold scan:

| Mode | Time |
|---|---|
| `regex` | 0.55s |
| `regex+bert` | 1.3s |
| `regex+gliner` | 3.7s |
| `bert` | 3m 23s |
| `gliner` | 10m+ |

## [0.2.1] - 2026-04-15

### Fixed

- Ignorelist exact-text matching is now case-insensitive. Entries like
  `text = "@EXAMPLE.COM"` correctly match findings like `admin@example.com`.
- `--format github` no longer emits per-file streaming lines (`path: ok`,
  `path: N finding(s)`) that polluted GitHub Actions' `::error::` parsing.
  Plain and TUI formats still stream as before.

## [0.2.0] - 2026-04-15

### Added

- `--model gliner` backend: GLiNER PII (knowledgator/gliner-pii-base-v1.0) via
  [gline-rs](https://github.com/fbilhaut/gline-rs). Zero-shot span NER tuned for
  PII — catches `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`,
  `CREDIT_CARD`, `IP_ADDRESS`, `US_PASSPORT`, `US_DRIVER_LICENSE`, `LOCATION`,
  `ORGANIZATION`, `MEDICAL_LICENSE`.
- README explaining the Presidio inspiration and hk / pre-commit use case.

### Changed

- Pinned `ort` to `=2.0.0-rc.9` and `ndarray` to `0.16` to match gline-rs.
- Bumped `tokenizers` to `0.21`.

## [0.1.1] - 2026-04-15

### Fixed

- Clippy lints (`unwrap_or` vs `unwrap_or_else`, `strip_prefix`, `SKIP_DIRS.contains`).
- Stale module doc comment in `src/ner.rs` still referenced the gliner backend.

### Added

- CHANGELOG.md (Keep a Changelog format).
- Release workflow now extracts the matching version section from CHANGELOG.md
  and uses it as the release body.

## [0.1.0] - 2026-04-15

### Added

- Initial release.
- Regex recognizers: `EMAIL_ADDRESS`, `CREDIT_CARD` (Luhn + entropy filter).
- NER backend via `ort` + `tokenizers` + Xenova/bert-base-NER (`--model bert`).
- Pure-regex mode (`--model regex`) for ML-free CI fast path.
- TOML ignorelist compatible with `phi.yaml` semantics: line, file, global, whole-file
  scopes plus email domain/username wildcards.
- `tunnletops migrate` subcommand — one-shot conversion from legacy `phi.yaml`.
- Streaming per-file output matching phi-scan's format.
- Output formats: `plain`, `github` (GitHub Actions), `tui` (colored diagnostics).
- `--fix-accept-all` for pre-commit hook integration.
- `--pr` mode: scan only files changed vs merge-base.
- Parallel file scanning via `rayon`.
- GitHub Actions CI (test + clippy + fmt) and release workflow for 5 targets
  (x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin, x86_64-windows)
  with SHA256 checksums.
