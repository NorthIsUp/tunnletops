//! NER backends for tunnletops.
//!
//! tunnletops pipes every file through a single shared `NerEngine`. The
//! backend is selected at startup via `--model`:
//!
//! * `regex`  — no NER, pure regex recognizers (fastest)
//! * `bert`   — Xenova/bert-base-NER quantized ONNX via `ort` + `tokenizers`
//!   (generic BIO NER over PER/ORG/LOC; noisy on code, best on prose)
//! * `gliner` — knowledgator/gliner-pii-base-v1.0 via `gline-rs` (zero-shot
//!   span NER tuned for PII: person/email/phone/SSN/credit-card/etc.)
//!
//! Default is `bert` for parity with phi-scan's observable surface.
//! `regex` is the speed-optimized CI fast path.
//! `gliner` is the PII-tuned option for more accurate catches in prose.

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
    /// knowledgator/gliner-pii-base-v1.0 — zero-shot span NER tuned for PII.
    /// Produces PERSON / EMAIL_ADDRESS / PHONE_NUMBER / US_SSN / CREDIT_CARD /
    /// IP_ADDRESS / US_PASSPORT / US_DRIVER_LICENSE / LOCATION / ORGANIZATION.
    Gliner,
}

pub struct NerEngine {
    backend: Backend,
}

enum Backend {
    None,
    Bert(Box<BertBackend>),
    Gliner(Box<GlinerBackend>),
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
            Model::Gliner => {
                tracing::debug!("NER backend: gliner");
                let gliner = GlinerBackend::load().context("loading GLiNER backend")?;
                Ok(Self {
                    backend: Backend::Gliner(Box::new(gliner)),
                })
            }
        }
    }

    pub fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        match &self.backend {
            Backend::None => Vec::new(),
            Backend::Bert(b) => b.analyze(file, text),
            Backend::Gliner(g) => g.analyze(file, text),
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
            let session = self.session.lock().unwrap();
            let outputs = session
                .run(ort::inputs![ids_tensor, attn_tensor, ttype_tensor]?)
                .context("ort run")?;
            let view = outputs[0]
                .try_extract_tensor::<f32>()
                .context("extracting logits")?;
            view.iter().copied().collect()
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

// =============================================================================
// GLiNER backend (knowledgator/gliner-pii-base-v1.0 via gline-rs)
// =============================================================================

const GLINER_REPO: &str = "knowledgator/gliner-pii-base-v1.0";
const GLINER_MODEL_FILE: &str = "onnx/model_quint8.onnx";
const GLINER_TOKENIZER_FILE: &str = "tokenizer.json";
const GLINER_THRESHOLD: f32 = 0.5;

/// GLiNER PII zero-shot labels and their Presidio entity type mappings.
/// The first element is what we feed to GLiNER; the second is what we emit
/// as `Finding::entity_type` so ignore rules port from phi.yaml cleanly.
const GLINER_LABELS: &[(&str, &str)] = &[
    ("person", "PERSON"),
    ("organization", "ORGANIZATION"),
    ("location", "LOCATION"),
    ("phone number", "PHONE_NUMBER"),
    ("email", "EMAIL_ADDRESS"),
    ("social security number", "US_SSN"),
    ("credit card number", "CREDIT_CARD"),
    ("ip address", "IP_ADDRESS"),
    ("passport number", "US_PASSPORT"),
    ("driver license", "US_DRIVER_LICENSE"),
    ("medical license number", "MEDICAL_LICENSE"),
];

pub struct GlinerBackend {
    model: Mutex<gliner::model::GLiNER<gliner::model::pipeline::span::SpanMode>>,
    entity_labels: Vec<String>,
    label_map: std::collections::HashMap<String, &'static str>,
}

// gliner::GLiNER holds an ort::Session (Send, not Sync); wrap in Mutex.
unsafe impl Sync for GlinerBackend {}

impl GlinerBackend {
    fn load() -> Result<Self> {
        use gliner::model::params::Parameters;
        use gliner::model::pipeline::span::SpanMode;
        use gliner::model::GLiNER;
        use orp::params::RuntimeParameters;

        let cache = cache_dir()?;
        fs::create_dir_all(&cache)
            .with_context(|| format!("creating cache dir {}", cache.display()))?;

        let model_path = cache.join("gliner-pii-base-v1.0.onnx");
        let tokenizer_path = cache.join("gliner-pii-base-v1.0.tokenizer.json");

        ensure_file(
            &model_path,
            &hf_url(GLINER_REPO, GLINER_MODEL_FILE),
            "GLiNER model (~187 MB)",
        )?;
        ensure_file(
            &tokenizer_path,
            &hf_url(GLINER_REPO, GLINER_TOKENIZER_FILE),
            "GLiNER tokenizer",
        )?;

        let params = Parameters::default().with_threshold(GLINER_THRESHOLD);
        let runtime = RuntimeParameters::default();
        let model = GLiNER::<SpanMode>::new(
            params,
            runtime,
            tokenizer_path.to_str().context("tokenizer path")?,
            model_path.to_str().context("model path")?,
        )
        .map_err(|e| anyhow::anyhow!("gline-rs load: {e}"))?;

        let entity_labels: Vec<String> = GLINER_LABELS.iter().map(|(g, _)| g.to_string()).collect();
        let label_map: std::collections::HashMap<String, &'static str> = GLINER_LABELS
            .iter()
            .map(|(g, p)| (g.to_string(), *p))
            .collect();

        tracing::debug!("GLiNER loaded: model={}", model_path.display());
        Ok(Self {
            model: Mutex::new(model),
            entity_labels,
            label_map,
        })
    }

    fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        use gliner::model::input::text::TextInput;

        // Process per-line so byte offsets map cleanly to (line_num, col).
        let lines: Vec<&str> = text.lines().collect();
        let mut inputs: Vec<&str> = Vec::with_capacity(lines.len());
        let mut input_line_idx: Vec<usize> = Vec::with_capacity(lines.len());
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.len() < 3 || line.len() > 2000 {
                continue;
            }
            inputs.push(line);
            input_line_idx.push(i);
        }
        if inputs.is_empty() {
            return Vec::new();
        }

        let label_refs: Vec<&str> = self.entity_labels.iter().map(|s| s.as_str()).collect();
        let text_input = match TextInput::from_str(&inputs, &label_refs) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("gliner TextInput error on {}: {e}", file);
                return Vec::new();
            }
        };

        let output = {
            let model = self.model.lock().unwrap();
            match model.inference(text_input) {
                Ok(o) => o,
                Err(e) => {
                    tracing::debug!("gliner inference error on {}: {e}", file);
                    return Vec::new();
                }
            }
        };

        let mut findings = Vec::new();
        for (seq_idx, spans) in output.spans.iter().enumerate() {
            let line_num = (input_line_idx[seq_idx] + 1) as u32;
            let line_content = lines[input_line_idx[seq_idx]];
            for span in spans {
                let Some(&entity_type) = self.label_map.get(span.class()) else {
                    continue;
                };
                let (start, end) = span.offsets();
                if start >= end || end > line_content.len() {
                    continue;
                }
                findings.push(Finding {
                    file: file.to_string(),
                    line_num,
                    col_start: start as u32,
                    col_end: end as u32,
                    entity_type: entity_type.to_string(),
                    text: span.text().to_string(),
                    score: span.probability(),
                    line_content: line_content.to_string(),
                });
            }
        }
        findings
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
