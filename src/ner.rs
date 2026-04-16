//! NER backends for tunnletops.
//!
//! tunnletops pipes every file through a single shared `NerEngine`. The
//! backend is selected at startup via `--model`:
//!
//! * `regex` — no NER, pure regex recognizers (fastest)
//! * `bert`  — Xenova/bert-base-NER quantized ONNX via `ort` + `tokenizers`
//!
//! Default is `bert` to preserve parity with phi-scan's observable surface.
//! `regex` exists as an explicit opt-out for CI paths that don't need NER.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use clap::ValueEnum;

use crate::finding::Finding;

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Model {
    /// Pure regex recognizers, no ML. Fastest. Use in CI / hot loops.
    Regex,
    /// Xenova/bert-base-NER quantized ONNX — BIO tagger over PER/ORG/LOC/MISC.
    /// Produces Presidio-compatible PERSON / ORGANIZATION / LOCATION entities.
    Bert,
}

pub struct NerEngine {
    backend: Backend,
}

enum Backend {
    None,
    Bert(Box<BertBackend>),
}

impl NerEngine {
    pub fn load(model: Model) -> Result<Self> {
        match model {
            Model::Regex => {
                tracing::debug!("NER backend: regex (disabled)");
                Ok(Self {
                    backend: Backend::None,
                })
            }
            Model::Bert => {
                tracing::debug!("NER backend: bert");
                let bert = BertBackend::load().context("loading BERT NER backend")?;
                Ok(Self {
                    backend: Backend::Bert(Box::new(bert)),
                })
            }
        }
    }

    pub fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        match &self.backend {
            Backend::None => Vec::new(),
            Backend::Bert(b) => b.analyze(file, text),
        }
    }
}

// =============================================================================
// BERT NER backend (Xenova/bert-base-NER via ort)
// =============================================================================

const BERT_REPO: &str = "Xenova/bert-base-NER";
const BERT_MODEL_FILE: &str = "onnx/model_quantized.onnx";
const BERT_TOKENIZER_FILE: &str = "tokenizer.json";
const MAX_TOKENS: usize = 510; // BERT limit 512 minus [CLS] + [SEP]

/// BIO label → Presidio entity type. MISC is intentionally dropped.
fn bio_to_entity(label: &str) -> Option<&'static str> {
    match label {
        "PER" => Some("PERSON"),
        "ORG" => Some("ORGANIZATION"),
        "LOC" => Some("LOCATION"),
        _ => None,
    }
}

/// BIO label ID table (dslim/bert-base-NER id2label).
const LABEL_TABLE: &[&str] = &[
    "O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
];

pub struct BertBackend {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
}

// tokenizers::Tokenizer is Send but not Sync; we wrap session in Mutex.
// Both Mutex fields make BertBackend Send+Sync.
unsafe impl Sync for BertBackend {}

impl BertBackend {
    fn load() -> Result<Self> {
        let cache = cache_dir()?;
        fs::create_dir_all(&cache)
            .with_context(|| format!("creating cache dir {}", cache.display()))?;

        let model_path = cache.join("bert-base-NER.onnx");
        let tokenizer_path = cache.join("bert-base-NER.tokenizer.json");

        ensure_file(
            &model_path,
            &hf_url(BERT_REPO, BERT_MODEL_FILE),
            "BERT NER model (~109 MB)",
        )?;
        ensure_file(
            &tokenizer_path,
            &hf_url(BERT_REPO, BERT_TOKENIZER_FILE),
            "BERT NER tokenizer",
        )?;

        let session = ort::session::Session::builder()
            .context("creating ort session builder")?
            .commit_from_file(&model_path)
            .with_context(|| format!("loading ONNX model from {}", model_path.display()))?;

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("tokenizer: {e}"))?;

        tracing::debug!("BERT NER loaded: model={}", model_path.display());
        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
        })
    }

    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        let mut all = Vec::new();
        let lines: Vec<&str> = text.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.len() < 3 {
                continue;
            }
            match self.analyze_line(file, (line_idx + 1) as u32, line, trimmed) {
                Ok(findings) => all.extend(findings),
                Err(e) => {
                    tracing::debug!("NER error on {}:{}: {e:#}", file, line_idx + 1);
                }
            }
        }
        all
    }

    fn analyze_line(
        &self,
        file: &str,
        line_num: u32,
        line_content: &str,
        trimmed: &str,
    ) -> Result<Vec<Finding>> {
        let encoding = self
            .tokenizer
            .encode(trimmed, true)
            .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;

        let ids = encoding.get_ids();
        if ids.len() > MAX_TOKENS + 2 {
            return Ok(Vec::new());
        }
        let mask = encoding.get_attention_mask();
        let offsets = encoding.get_offsets();

        let n = ids.len();
        let input_ids: Vec<i64> = ids.iter().map(|&x| x as i64).collect();
        let attention_mask: Vec<i64> = mask.iter().map(|&x| x as i64).collect();

        let input_ids_arr =
            ndarray::Array2::from_shape_vec((1, n), input_ids).context("input_ids shape")?;
        let attn_arr = ndarray::Array2::from_shape_vec((1, n), attention_mask)
            .context("attention_mask shape")?;
        let token_type_ids = vec![0i64; n];
        let token_type_arr = ndarray::Array2::from_shape_vec((1, n), token_type_ids)
            .context("token_type_ids shape")?;

        let ids_tensor =
            ort::value::Tensor::<i64>::from_array(input_ids_arr).context("ids tensor")?;
        let attn_tensor = ort::value::Tensor::<i64>::from_array(attn_arr).context("attn tensor")?;
        let ttype_tensor =
            ort::value::Tensor::<i64>::from_array(token_type_arr).context("token_type tensor")?;

        let logits_owned: Vec<f32> = {
            let mut session = self.session.lock().unwrap();
            let outputs = session
                .run(ort::inputs![ids_tensor, attn_tensor, ttype_tensor])
                .context("ort run")?;
            let (_shape, flat) = outputs[0]
                .try_extract_tensor::<f32>()
                .context("extracting logits")?;
            flat.to_vec()
        };
        let logits_flat = &logits_owned;
        // Output shape: [1, seq_len, num_classes]. We know both from input.
        let seq_len = n;
        let num_classes = LABEL_TABLE.len();

        let indent = line_content.len() - line_content.trim_start().len();
        let mut findings = Vec::new();
        let mut current: Option<(usize, usize, &str)> = None; // (start_token, end_token, entity)

        for t in 0..seq_len {
            let mut best_class = 0usize;
            let mut best_score = f32::NEG_INFINITY;
            let row_offset = t * num_classes;
            for c in 0..num_classes {
                let s = logits_flat[row_offset + c];
                if s > best_score {
                    best_score = s;
                    best_class = c;
                }
            }
            let label = LABEL_TABLE.get(best_class).copied().unwrap_or("O");

            if let Some(stripped) = label.strip_prefix("B-") {
                if let Some((start, end, ent)) = current.take() {
                    if let Some(f) = self.span_to_finding(
                        file,
                        line_num,
                        line_content,
                        trimmed,
                        indent,
                        offsets,
                        start,
                        end,
                        ent,
                    ) {
                        findings.push(f);
                    }
                }
                current = Some((t, t, stripped));
            } else if let Some(stripped) = label.strip_prefix("I-") {
                if let Some((start, end, ent)) = &current {
                    if *ent == stripped {
                        current = Some((*start, t, ent));
                    } else {
                        if let Some(f) = self.span_to_finding(
                            file,
                            line_num,
                            line_content,
                            trimmed,
                            indent,
                            offsets,
                            *start,
                            *end,
                            ent,
                        ) {
                            findings.push(f);
                        }
                        current = Some((t, t, stripped));
                    }
                } else {
                    current = Some((t, t, stripped));
                }
            } else {
                // "O"
                if let Some((start, end, ent)) = current.take() {
                    if let Some(f) = self.span_to_finding(
                        file,
                        line_num,
                        line_content,
                        trimmed,
                        indent,
                        offsets,
                        start,
                        end,
                        ent,
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
        // flush
        if let Some((start, end, ent)) = current.take() {
            if let Some(f) = self.span_to_finding(
                file,
                line_num,
                line_content,
                trimmed,
                indent,
                offsets,
                start,
                end,
                ent,
            ) {
                findings.push(f);
            }
        }

        Ok(findings)
    }

    #[allow(clippy::too_many_arguments)]
    fn span_to_finding(
        &self,
        file: &str,
        line_num: u32,
        line_content: &str,
        trimmed: &str,
        indent: usize,
        offsets: &[(usize, usize)],
        start_tok: usize,
        end_tok: usize,
        bio_entity: &str,
    ) -> Option<Finding> {
        let entity_type = bio_to_entity(bio_entity)?;
        let byte_start = offsets.get(start_tok)?.0;
        let byte_end = offsets.get(end_tok)?.1;
        if byte_start >= byte_end || byte_end > trimmed.len() {
            return None;
        }
        let text = trimmed[byte_start..byte_end].to_string();
        if text.trim().is_empty() || text.len() < 2 {
            return None;
        }
        let col_start = (indent + byte_start) as u32;
        let col_end = (indent + byte_end) as u32;
        Some(Finding {
            file: file.to_string(),
            line_num,
            col_start,
            col_end,
            entity_type: entity_type.to_string(),
            text,
            score: 0.85,
            line_content: line_content.to_string(),
        })
    }
}

fn cache_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("ai", "northisup", "tunnletops")
        .context("cannot locate user cache dir")?;
    Ok(dirs.cache_dir().to_path_buf())
}

fn hf_url(repo: &str, file: &str) -> String {
    format!("https://huggingface.co/{repo}/resolve/main/{file}")
}

fn ensure_file(path: &Path, url: &str, label: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    eprintln!("tunnletops: downloading {label} from {url}");
    let mut resp = ureq::get(url)
        .call()
        .with_context(|| format!("downloading {label}"))?
        .into_reader();
    let mut buf = Vec::new();
    resp.read_to_end(&mut buf)
        .context("reading download body")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(path, &buf).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("tunnletops: cached {label} at {}", path.display());
    Ok(())
}
