# tunnletops

Fast PHI/PII scanner for source repositories. Written in Rust for hk / pre-commit hooks.

**Status:** v0.1.x — actively evolving.

## Why

Presidio is excellent for scanning long-form text and structured data. It's less well suited to scanning a source repository on every commit:

- Python startup + loading spaCy's `en_core_web_lg` (~740 MB) takes multiple seconds before anything is scanned.
- Large monorepos need a per-file cache file to stay tolerable. That cache file itself becomes a merge-conflict source on busy branches.
- Most PHI in code (test fixtures, seed files, docs) is regex-detectable. The NER layer does a lot of work for findings that get filtered out by score thresholds anyway.

tunnletops is a Presidio-inspired scanner designed specifically for the pre-commit path:

- **Sub-second cold scan** of a full backend across thousands of files (regex-only mode).
- **No cache file.** Fast enough that caching is pointless, which removes the merge-conflict problem at its source.
- **Single static binary.** Drop it into a `hk.pkl` step or a pre-commit hook and go.
- **Optional NER** via ONNX Runtime — opt in with `--model bert` or `--model gliner` when you need it; opt out with `--model regex` when you don't.
- **Presidio-compatible entity types.** `EMAIL_ADDRESS`, `CREDIT_CARD`, `PHONE_NUMBER`, `PERSON`, etc. — so your existing `.baselines/phi.yaml` ignores port cleanly.

## Inspiration

Tunnletops is structurally inspired by [Microsoft Presidio](https://github.com/microsoft/presidio):

- The **Recognizer** trait (regex + validator + context scoring) follows Presidio's design.
- **Entity names** match Presidio's vocabulary so ignorelists are portable.
- The **AnalyzerEngine → BatchAnalyzerEngine** pattern is reflected in tunnletops's pipeline (single pass through every file, ML model loaded once).

The name is a nod to the etymology: `presidio` is Spanish for a fortified garrison — tunnletops points to what's above the tunnels those walls protect.

## Install

```bash
# Download the binary for your platform from the latest release:
curl -L -o tunnletops https://github.com/NorthIsUp/tunnletops/releases/latest/download/tunnletops-aarch64-darwin
chmod +x tunnletops
```

Available targets: `aarch64-darwin`, `x86_64-linux`, `aarch64-linux`, `x86_64-windows.exe`.

Each release ships a `checksums-sha256.txt` for verification.

Or build from source:

```bash
cargo install --git https://github.com/NorthIsUp/tunnletops
```

## Usage

```bash
# Scan the entire repo, regex only (fastest):
tunnletops --model regex

# Scan, with NER enabled:
tunnletops --model bert

# Only scan files changed in the current PR:
tunnletops --pr

# Auto-ignore every finding to bootstrap an ignorelist:
tunnletops --fix-accept-all

# GitHub Actions-formatted output:
tunnletops --format github
```

## Integration with hk

Drop this into `hk.pkl`:

```pkl
steps {
    ["phi-scan"] = new Step {
        check = "tunnletops --format github"
        fix = "tunnletops --format plain --fix-accept-all"
        pre_commit = true
    }
}
```

## Ignorelist format

`.baselines/phi.toml` (TOML, line/file/global scopes plus whole-file skips):

```toml
[[ignored]]
scope = "file"
file = "backend/fixtures/seed_users.py"
entity_type = "EMAIL_ADDRESS"
text = "test@example.com"

[[ignored]]
scope = "global"
entity_type = "EMAIL_ADDRESS"
text = "@clarahealth.com"   # leading @ = match any email with this domain

[[ignored]]
type = "file"
file = "docs/sample-data.json"   # skip this file entirely
```

Migrate an existing Presidio-era `phi.yaml`:

```bash
tunnletops migrate .baselines/phi.yaml .baselines/phi.toml
```

## License

MIT.
