# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
