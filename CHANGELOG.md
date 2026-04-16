# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
