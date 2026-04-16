use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

pub const MAX_FILE_SIZE: usize = 1_000_000;

const SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot", "lock", "pyc", "pyo",
    "so", "dylib", "bin", "pdf", "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "jar", "war", "ear",
    "class", "o", "a", "mo", "mp3", "mp4", "avi", "mov", "wmv", "flv", "webm", "webp", "bmp",
    "tiff", "psd",
];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".baselines",
];

fn has_skipped_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            let lower = ext.to_ascii_lowercase();
            SKIP_EXTENSIONS.iter().any(|s| *s == lower)
        })
}

fn has_skipped_dir_component(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| SKIP_DIRS.contains(&s))
    })
}

pub fn discover_files(paths: &[PathBuf], pr_mode: bool) -> Result<Vec<PathBuf>> {
    if pr_mode {
        return discover_pr_files();
    }
    discover_git_files(paths)
}

fn discover_git_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    // Use ripgrep's `ignore` crate to respect .gitignore, .ignore,
    // .git/info/exclude, and global git ignore. Works outside git too.
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    let (first, rest) = roots.split_first().expect("at least one root");
    let mut builder = ignore::WalkBuilder::new(first);
    for p in rest {
        builder.add(p);
    }
    // Don't hide dotfiles — let .gitignore decide. Files like .github/*
    // should still be scanned.
    builder.hidden(false);
    builder.standard_filters(true);

    let mut files = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path().to_path_buf();
        if has_skipped_extension(&path) || has_skipped_dir_component(&path) {
            continue;
        }
        files.push(path);
    }
    Ok(files)
}

fn discover_pr_files() -> Result<Vec<PathBuf>> {
    let root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("git rev-parse")?;
    if !root.status.success() {
        anyhow::bail!("not inside a git repo");
    }
    let root = PathBuf::from(String::from_utf8(root.stdout)?.trim());
    let script = root.join("scripts").join("git-pr-changed");
    let out = Command::new(&script)
        .output()
        .with_context(|| format!("running {}", script.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "git-pr-changed failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mut files = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.is_empty() {
            continue;
        }
        let p = PathBuf::from(line);
        if has_skipped_extension(&p) || has_skipped_dir_component(&p) {
            continue;
        }
        files.push(p);
    }
    Ok(files)
}
