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

use anyhow::{Context, Result};
use clap::ValueEnum;

use crate::finding::Finding;
use crate::pool::Pool;

/// How many parallel sessions to build for each NER backend.
/// Capped at 4 to keep memory in check — one BERT session is ~200MB and one
/// GLiNER session is ~400MB resident.
fn pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(4))
        .unwrap_or(2)
}

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
    /// Regex candidates + BERT validation. Broad regexes find candidates;
    /// BERT runs only on candidate lines. Fast, but BERT can only confirm
    /// PERSON/ORG/LOC, so PHONE/SSN/IP candidates are dropped.
    #[value(name = "regex+bert")]
    RegexBert,
    /// Regex candidates + GLiNER validation. Broad regexes find candidates;
    /// GLiNER validates each on the candidate's line. Best precision/recall
    /// trade-off for PII.
    #[value(name = "regex+gliner")]
    RegexGliner,
}

/// Which NER engine to load, independent of whether we're in hybrid mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NerKind {
    Bert,
    Gliner,
}

impl Model {
    pub fn ner_kind(self) -> Option<NerKind> {
        match self {
            Model::Regex => None,
            Model::Bert | Model::RegexBert => Some(NerKind::Bert),
            Model::Gliner | Model::RegexGliner => Some(NerKind::Gliner),
        }
    }

    pub fn is_hybrid(self) -> bool {
        matches!(self, Model::RegexBert | Model::RegexGliner)
    }
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
    pub fn load(kind: Option<NerKind>, threshold: Option<f32>) -> Result<Self> {
        match kind {
            None => {
                tracing::debug!("NER backend: regex (disabled)");
                Ok(Self {
                    backend: Backend::None,
                })
            }
            Some(NerKind::Bert) => {
                tracing::debug!("NER backend: bert");
                let bert = BertBackend::load().context("loading BERT NER backend")?;
                Ok(Self {
                    backend: Backend::Bert(Box::new(bert)),
                })
            }
            Some(NerKind::Gliner) => {
                tracing::debug!("NER backend: gliner");
                let gliner = GlinerBackend::load(threshold.unwrap_or(GLINER_THRESHOLD))
                    .context("loading GLiNER backend")?;
                Ok(Self {
                    backend: Backend::Gliner(Box::new(gliner)),
                })
            }
        }
    }

    pub fn analyze(&self, file: &str, text: &str) -> Vec<Finding> {
        self.analyze_with_filter(file, text, None)
    }

    /// Analyze only the given set of 1-based line numbers (hybrid mode speedup).
    /// If `lines` is `None`, analyzes the full text.
    pub fn analyze_with_filter(
        &self,
        file: &str,
        text: &str,
        lines: Option<&std::collections::HashSet<u32>>,
    ) -> Vec<Finding> {
        match &self.backend {
            Backend::None => Vec::new(),
            Backend::Bert(b) => b.analyze_with_filter(file, text, lines),
            Backend::Gliner(g) => g.analyze_with_filter(file, text, lines),
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

/// How many lines we pack into one BERT forward pass. Bigger = fewer ort
/// calls = less per-call overhead, but more padded tokens on short lines.
const BERT_BATCH_SIZE: usize = 32;

pub struct BertBackend {
    sessions: Pool<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
}

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

        let n = pool_size();
        let model_path_clone = model_path.clone();
        let sessions = Pool::new(n, move || {
            ort::session::Session::builder()
                .context("creating ort session builder")?
                .commit_from_file(&model_path_clone)
                .with_context(|| format!("loading ONNX model from {}", model_path_clone.display()))
        })?;

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("tokenizer: {e}"))?;

        tracing::debug!(
            "BERT NER loaded: model={} pool_size={}",
            model_path.display(),
            n
        );
        Ok(Self {
            sessions,
            tokenizer,
        })
    }

    fn analyze_with_filter(
        &self,
        file: &str,
        text: &str,
        line_filter: Option<&std::collections::HashSet<u32>>,
    ) -> Vec<Finding> {
        let lines: Vec<&str> = text.lines().collect();

        // Collect lines to process. We keep the original line index and line content
        // alongside the trimmed text that goes to the tokenizer.
        let inputs: Vec<(u32, &str, &str)> = lines
            .iter()
            .enumerate()
            .filter_map(|(i, line)| {
                let line_num = (i + 1) as u32;
                if let Some(filter) = line_filter {
                    if !filter.contains(&line_num) {
                        return None;
                    }
                }
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.len() < 3 {
                    return None;
                }
                Some((line_num, *line, trimmed))
            })
            .collect();

        let mut findings = Vec::new();
        for chunk in inputs.chunks(BERT_BATCH_SIZE) {
            match self.analyze_chunk(file, chunk) {
                Ok(fs) => findings.extend(fs),
                Err(e) => tracing::debug!("BERT chunk error in {file}: {e:#}"),
            }
        }
        findings
    }

    fn analyze_chunk(&self, file: &str, chunk: &[(u32, &str, &str)]) -> Result<Vec<Finding>> {
        let texts: Vec<&str> = chunk.iter().map(|(_, _, t)| *t).collect();
        let encodings = self
            .tokenizer
            .encode_batch(texts, true)
            .map_err(|e| anyhow::anyhow!("encode_batch: {e}"))?;

        // Drop overlong rows (rare).
        let kept: Vec<usize> = encodings
            .iter()
            .enumerate()
            .filter(|(_, e)| e.get_ids().len() <= MAX_TOKENS + 2)
            .map(|(i, _)| i)
            .collect();
        if kept.is_empty() {
            return Ok(Vec::new());
        }

        let max_len = kept
            .iter()
            .map(|&i| encodings[i].get_ids().len())
            .max()
            .unwrap();
        let batch = kept.len();
        let num_classes = LABEL_TABLE.len();

        // Pack padded tensors. PAD token id = 0 for BERT.
        let mut input_ids = vec![0i64; batch * max_len];
        let mut attn = vec![0i64; batch * max_len];
        for (row, &i) in kept.iter().enumerate() {
            let enc = &encodings[i];
            let ids = enc.get_ids();
            let mask = enc.get_attention_mask();
            for (col, (&id, &m)) in ids.iter().zip(mask.iter()).enumerate() {
                input_ids[row * max_len + col] = id as i64;
                attn[row * max_len + col] = m as i64;
            }
        }
        let ttype = vec![0i64; batch * max_len];

        let ids_arr =
            ndarray::Array2::from_shape_vec((batch, max_len), input_ids).context("ids shape")?;
        let attn_arr =
            ndarray::Array2::from_shape_vec((batch, max_len), attn).context("attn shape")?;
        let ttype_arr =
            ndarray::Array2::from_shape_vec((batch, max_len), ttype).context("ttype shape")?;

        let ids_tensor = ort::value::Tensor::<i64>::from_array(ids_arr).context("ids tensor")?;
        let attn_tensor = ort::value::Tensor::<i64>::from_array(attn_arr).context("attn tensor")?;
        let ttype_tensor =
            ort::value::Tensor::<i64>::from_array(ttype_arr).context("ttype tensor")?;

        let logits: Vec<f32> = {
            let session = self.sessions.checkout();
            let outputs = session
                .run(ort::inputs![ids_tensor, attn_tensor, ttype_tensor]?)
                .context("ort run")?;
            let view = outputs[0]
                .try_extract_tensor::<f32>()
                .context("extracting logits")?;
            view.iter().copied().collect()
        };

        // Decode each row with its actual (unpadded) length.
        let mut findings = Vec::new();
        for (row, &i) in kept.iter().enumerate() {
            let (line_num, line_content, trimmed) = chunk[i];
            let enc = &encodings[i];
            let actual_len = enc.get_ids().len();
            let row_start = row * max_len * num_classes;
            let row_logits = &logits[row_start..row_start + actual_len * num_classes];
            findings.extend(decode_bio_row(
                file,
                line_num,
                line_content,
                trimmed,
                enc.get_offsets(),
                row_logits,
                actual_len,
                num_classes,
            ));
        }
        Ok(findings)
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_bio_row(
    file: &str,
    line_num: u32,
    line_content: &str,
    trimmed: &str,
    offsets: &[(usize, usize)],
    logits: &[f32],
    seq_len: usize,
    num_classes: usize,
) -> Vec<Finding> {
    let indent = line_content.len() - line_content.trim_start().len();
    let mut findings = Vec::new();
    let mut current: Option<(usize, usize, &str)> = None;

    let flush = |current: &mut Option<(usize, usize, &str)>, out: &mut Vec<Finding>| {
        if let Some((start, end, ent)) = current.take() {
            if let Some(f) = span_to_finding(
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
                out.push(f);
            }
        }
    };

    for t in 0..seq_len {
        let mut best_class = 0usize;
        let mut best_score = f32::NEG_INFINITY;
        for c in 0..num_classes {
            let s = logits[t * num_classes + c];
            if s > best_score {
                best_score = s;
                best_class = c;
            }
        }
        let label = LABEL_TABLE.get(best_class).copied().unwrap_or("O");

        // BILOU scheme: B-X begin, I-X inside, L-X last, U-X unit (single-token).
        // Presidio's HuggingFaceNerRecognizer strips all four prefixes.
        let prefixes = ["B-", "I-", "L-", "U-"];
        let stripped = prefixes
            .iter()
            .find_map(|p| label.strip_prefix(p).map(|rest| (*p, rest)));
        match stripped {
            Some(("U-", rest)) => {
                // Unit: flush current, emit this single-token span, reset.
                flush(&mut current, &mut findings);
                current = Some((t, t, rest));
                flush(&mut current, &mut findings);
            }
            Some(("L-", rest)) => {
                // Last: extend current if same type, otherwise start-and-end.
                if let Some((start, _, ent)) = &current {
                    if *ent == rest {
                        current = Some((*start, t, ent));
                    } else {
                        flush(&mut current, &mut findings);
                        current = Some((t, t, rest));
                    }
                } else {
                    current = Some((t, t, rest));
                }
                flush(&mut current, &mut findings);
            }
            Some(("B-", rest)) => {
                flush(&mut current, &mut findings);
                current = Some((t, t, rest));
            }
            Some(("I-", rest)) => {
                if let Some((start, _, ent)) = &current {
                    if *ent == rest {
                        current = Some((*start, t, ent));
                    } else {
                        flush(&mut current, &mut findings);
                        current = Some((t, t, rest));
                    }
                } else {
                    current = Some((t, t, rest));
                }
            }
            _ => {
                // "O" or anything else — flush.
                flush(&mut current, &mut findings);
            }
        }
    }
    flush(&mut current, &mut findings);
    findings
}

#[allow(clippy::too_many_arguments)]
fn span_to_finding(
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
    models: Pool<gliner::model::GLiNER<gliner::model::pipeline::span::SpanMode>>,
    entity_labels: Vec<String>,
    label_map: std::collections::HashMap<String, &'static str>,
}

impl GlinerBackend {
    fn load(threshold: f32) -> Result<Self> {
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

        // GLiNER sessions are larger (~400MB resident). Cap the pool at 2 —
        // past that we blow the RAM budget without a matching throughput gain
        // since gline-rs inference is already internally parallel.
        let n = pool_size().min(2);
        let mp = model_path.clone();
        let tp = tokenizer_path.clone();
        let models = Pool::new(n, move || {
            let params = Parameters::default().with_threshold(threshold);
            let runtime = RuntimeParameters::default();
            GLiNER::<SpanMode>::new(
                params,
                runtime,
                tp.to_str().context("tokenizer path")?,
                mp.to_str().context("model path")?,
            )
            .map_err(|e| anyhow::anyhow!("gline-rs load: {e}"))
        })?;

        let entity_labels: Vec<String> = GLINER_LABELS.iter().map(|(g, _)| g.to_string()).collect();
        let label_map: std::collections::HashMap<String, &'static str> = GLINER_LABELS
            .iter()
            .map(|(g, p)| (g.to_string(), *p))
            .collect();

        tracing::debug!(
            "GLiNER loaded: model={} pool_size={}",
            model_path.display(),
            n
        );
        Ok(Self {
            models,
            entity_labels,
            label_map,
        })
    }

    fn analyze_with_filter(
        &self,
        file: &str,
        text: &str,
        line_filter: Option<&std::collections::HashSet<u32>>,
    ) -> Vec<Finding> {
        use gliner::model::input::text::TextInput;

        // Process per-line so byte offsets map cleanly to (line_num, col).
        let lines: Vec<&str> = text.lines().collect();
        let mut inputs: Vec<&str> = Vec::with_capacity(lines.len());
        let mut input_line_idx: Vec<usize> = Vec::with_capacity(lines.len());
        for (i, line) in lines.iter().enumerate() {
            let line_num = (i + 1) as u32;
            if let Some(filter) = line_filter {
                if !filter.contains(&line_num) {
                    continue;
                }
            }
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
            let model = self.models.checkout();
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
