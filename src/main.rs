use clap::Parser;
use colored::Colorize;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "proxy")]
use std::sync::Arc;

use anon_pii::cli::{Cli, Commands, Format};
use anon_pii::config::RecognizerConfigFile;
use anon_pii::detection::{
    Anonymizer, Detection, MaskConfig, Operator, decrypt_encrypted, parse_encrypt_key,
};
use anon_pii::format::{DetectedFormat, detect_format, detect_json_indent};
use anon_pii::mapping::Mapping;
use anon_pii::patterns::{MAX_INPUT_SIZE, PATTERNS};
#[cfg(feature = "proxy")]
use anon_pii::proxy;

// ─── Default mapping path ────────────────────────────────────────────────────

fn default_mapping_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".anon-pii")
}

fn default_mapping_path() -> PathBuf {
    default_mapping_dir().join("mapping.json")
}

// ─── I/O helpers ────────────────────────────────────────────────────────────

fn read_input(path: Option<&PathBuf>) -> io::Result<String> {
    match path {
        Some(p) => {
            let size = fs::metadata(p)?.len();
            if size > MAX_INPUT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "File too large: {} bytes (max {} bytes)",
                        size, MAX_INPUT_SIZE
                    ),
                ));
            }
            fs::read_to_string(p)
        }
        None => {
            let mut buffer = String::new();
            io::stdin()
                .take(MAX_INPUT_SIZE)
                .read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn write_output(path: Option<&PathBuf>, content: &str) -> io::Result<()> {
    match path {
        Some(p) => fs::write(p, content),
        None => {
            print!("{}", content);
            if !content.ends_with('\n') {
                println!();
            }
            io::stdout().flush()
        }
    }
}

fn share_event_log_path() -> PathBuf {
    default_mapping_dir().join("events.jsonl")
}

/// Best-effort local event logging for measurement.
/// Never includes PII; appends JSON lines under ~/.anon-pii/events.jsonl.
fn append_share_event(event: &str, props: serde_json::Value) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let dir = default_mapping_dir();
    let _ = create_private_dir(&dir);

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let line = json!({
        "ts_ms": ts_ms,
        "event": event,
        "props": props,
    });

    let path = share_event_log_path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
        {
            let _ = writeln!(f, "{}", line);
        }
    }

    #[cfg(not(unix))]
    {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

fn max_consecutive_backticks(s: &str) -> usize {
    let mut max_run = 0usize;
    let mut run = 0usize;
    for ch in s.chars() {
        if ch == '`' {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    max_run
}

fn choose_markdown_fence(s: &str) -> String {
    let n = (max_consecutive_backticks(s) + 1).max(3);
    "`".repeat(n)
}

fn summarize_detections(
    detections: &[Detection],
) -> (usize, std::collections::BTreeMap<String, usize>) {
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut by_type: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    for d in detections {
        if seen.insert((d.entity_type.to_string(), d.original.clone())) {
            *by_type.entry(d.entity_type.to_string()).or_insert(0) += 1;
        }
    }

    (seen.len(), by_type)
}

fn render_share_markdown(result: &str, detections: &[Detection], format_name: &str) -> String {
    let (unique_count, by_type) = summarize_detections(detections);
    let types_count = by_type.len();

    let summary = if unique_count == 0 {
        "Detected 0 entities.".to_string()
    } else {
        let mut parts: Vec<String> = Vec::with_capacity(by_type.len());
        for (t, c) in by_type {
            parts.push(format!("{t} x{c}"));
        }
        let types_suffix = if types_count > 1 {
            format!(" across {types_count} types")
        } else {
            String::new()
        };
        format!(
            "Detected {unique_count} unique entit{}{}: {}.",
            if unique_count == 1 { "y" } else { "ies" },
            types_suffix,
            parts.join(", ")
        )
    };

    let fence = choose_markdown_fence(result);
    let lang = match format_name {
        "json" => "json",
        "sql" => "sql",
        "csv" => "csv",
        _ => "text",
    };

    let mut md = String::new();
    md.push_str("Anonymized with `anon-pii`.\n\n");
    md.push_str(&summary);
    md.push_str("\n\n");
    md.push_str(&fence);
    md.push_str(lang);
    md.push('\n');
    md.push_str(result.trim_end_matches('\n'));
    md.push('\n');
    md.push_str(&fence);
    md.push('\n');
    md
}

fn run_clipboard_command(cmd: &str, args: &[&str], text: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn {cmd}: {e}"))?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| "failed to open stdin".to_string())?
        .write_all(text.as_bytes())
        .map_err(|e| format!("failed to write to {cmd}: {e}"))?;

    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for {cmd}: {e}"))?;
    if !status.success() {
        return Err(format!("{cmd} exited with {status}"));
    }
    Ok(())
}

fn copy_to_clipboard_best_effort(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        run_clipboard_command("pbcopy", &[], text)
    }

    #[cfg(target_os = "windows")]
    {
        run_clipboard_command("clip", &[], text)
    }

    #[cfg(target_os = "linux")]
    {
        if run_clipboard_command("wl-copy", &[], text).is_ok() {
            return Ok(());
        }
        if run_clipboard_command("xclip", &["-selection", "clipboard"], text).is_ok() {
            return Ok(());
        }
        if run_clipboard_command("xsel", &["--clipboard", "--input"], text).is_ok() {
            return Ok(());
        }
        Err("no clipboard helper found (tried wl-copy, xclip, xsel)".to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = text;
        Err("clipboard copy not supported on this platform".to_string())
    }
}

/// Create directory with mode 0o700 (owner-only) on Unix.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write mapping file atomically via temp-file-then-rename.
/// This eliminates TOCTOU races: no window between check and open, and
/// rename() replaces the directory entry atomically (even if target is a symlink,
/// the symlink itself is replaced, not followed).
fn write_mapping_file(path: &PathBuf, content: &str) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mapping path has no parent directory",
        )
    })?;

    // Write to a temp file in the same directory (same filesystem = atomic rename)
    let tmp_path = dir.join(".mapping.json.tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, content)?;
    }

    // Atomic rename — replaces target directory entry, never follows symlinks
    fs::rename(&tmp_path, path)?;
    Ok(())
}

// ─── Verbose output ─────────────────────────────────────────────────────────

/// Mask a PII value for safe display: show first and last char with `***` in between.
/// Short values (≤2 chars) are fully masked.
fn mask_pii(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 2 {
        "*".repeat(chars.len())
    } else {
        format!("{}***{}", chars[0], chars[chars.len() - 1])
    }
}

fn print_detections(detections: &[Detection]) {
    if detections.is_empty() {
        return;
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<&Detection> = detections
        .iter()
        .filter(|d| seen.insert((d.entity_type.as_ref(), &d.original)))
        .collect();

    let type_width = unique
        .iter()
        .map(|d| d.entity_type.len())
        .max()
        .unwrap_or(10);
    let val_width = 40;

    eprintln!();
    eprintln!(
        "  {:<tw$}  {:<vw$}  {}",
        "Entity".bold(),
        "Original".bold(),
        "Score".bold(),
        tw = type_width,
        vw = val_width
    );
    eprintln!(
        "  {:<tw$}  {:<vw$}  ─────",
        "─".repeat(type_width),
        "─".repeat(val_width),
        tw = type_width,
        vw = val_width
    );

    for det in &unique {
        let masked = mask_pii(&det.original);
        let display: String = if masked.chars().count() > val_width {
            let s: String = masked.chars().take(val_width - 1).collect();
            format!("{s}…")
        } else {
            masked
        };

        eprintln!(
            "  {:<tw$}  {:<vw$}  {:.2}",
            det.entity_type.green(),
            display,
            det.score,
            tw = type_width,
            vw = val_width
        );
    }
    eprintln!();
}

// ─── Batched text processing ────────────────────────────────────────────────

/// Process text input line-by-line with batched NER inference.
///
/// Splits input into lines, batches them according to `batch_size`, and uses
/// `Anonymizer::anonymize_texts()` to process each batch with efficient NER inference.
/// Results are reassembled preserving newlines and line order.
///
/// When `batch_size` is 0, falls back to unbatched `anonymize_text()` on the whole input.
#[allow(dead_code)] // Used only in tests and with ner/ner-lite features
fn process_text_batched(
    anonymizer: &mut Anonymizer,
    content: &str,
    batch_size: usize,
) -> (String, Vec<Detection>) {
    if content.is_empty() {
        return (String::new(), Vec::new());
    }

    // batch_size 0 means no batching - process whole input at once
    if batch_size == 0 {
        return anonymizer.anonymize_text(content);
    }

    let trailing_newline = content.ends_with('\n');
    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        return (String::new(), Vec::new());
    }

    let mut all_results: Vec<String> = Vec::with_capacity(lines.len());
    let mut all_detections: Vec<Detection> = Vec::new();

    // Process in batches
    for batch in lines.chunks(batch_size) {
        let batch_results = anonymizer.anonymize_texts(batch);
        for (anonymized, detections) in batch_results {
            all_results.push(anonymized);
            all_detections.extend(detections);
        }
    }

    // Reassemble with newlines
    let mut result = all_results.join("\n");
    if trailing_newline {
        result.push('\n');
    }

    (result, all_detections)
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Restore {
            input_positional,
            input,
            mapping,
            output,
            decrypt_key,
        }) => {
            let resolved_input = input.or(input_positional);
            let content = read_input(resolved_input.as_ref())?;

            let dk = decrypt_key
                .as_deref()
                .map(|hex| {
                    parse_encrypt_key(hex)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
                })
                .transpose()?;

            let mapping_path = mapping.unwrap_or_else(default_mapping_path);
            let has_mapping = mapping_path.exists();

            let mut result = content.clone();

            if has_mapping {
                let mapping_content = fs::read_to_string(&mapping_path)?;
                let mut m: Mapping = match serde_json::from_str(&mapping_content) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Error: invalid mapping file: {e}");
                        std::process::exit(1);
                    }
                };
                m.rebuild_caches();
                result = m.restore(&result);
                eprintln!("Restored {} entities from mapping", m.mappings.len());
            }

            if let Some(key) = &dk {
                result = decrypt_encrypted(&result, key);
            }

            if !has_mapping && dk.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no mapping file found at {} and no --decrypt-key provided",
                        mapping_path.display()
                    ),
                ));
            }

            write_output(output.as_ref(), &result)?;
        }
        #[cfg(feature = "ner")]
        Some(Commands::DownloadModel { model_dir }) => {
            let mut config = anon_pii::ner::NerConfig::default();
            if let Some(dir) = model_dir {
                config.model_dir = dir;
            }
            eprintln!("Downloading NER model...");
            if let Err(e) = anon_pii::ner::download::download_model(&config) {
                eprintln!("Error downloading model: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::UpdateNames { file, replace }) => {
            let content = fs::read_to_string(&file).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot read {}: {e}", file.display()))
            })?;

            let mut firstnames: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            let mut lastnames: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();

            for (i, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // Skip header row
                if i == 0 {
                    let lower = line.to_lowercase();
                    if lower.contains("firstname")
                        || lower.contains("lastname")
                        || lower.contains("first_name")
                        || lower.contains("last_name")
                        || lower.contains("prénom")
                        || lower.contains("nom")
                    {
                        continue;
                    }
                }
                let parts: Vec<&str> = line.splitn(2, ',').collect();
                if parts.len() == 2 {
                    let first = parts[0].trim();
                    let last = parts[1].trim();
                    if !first.is_empty() {
                        firstnames.insert(first.to_string());
                    }
                    if !last.is_empty() {
                        lastnames.insert(last.to_string());
                    }
                } else {
                    // Single column — treat as firstname
                    let name = parts[0].trim();
                    if !name.is_empty() {
                        firstnames.insert(name.to_string());
                    }
                }
            }

            let anon_dir = default_mapping_dir();
            create_private_dir(&anon_dir)?;

            let first_path = anon_dir.join("firstnames.txt");
            let last_path = anon_dir.join("lastnames.txt");

            // Merge with existing if not --replace
            if !replace {
                if let Ok(existing) = fs::read_to_string(&first_path) {
                    for line in existing.lines() {
                        let name = line.trim();
                        if !name.is_empty() && !name.starts_with('#') {
                            firstnames.insert(name.to_string());
                        }
                    }
                }
                if let Ok(existing) = fs::read_to_string(&last_path) {
                    for line in existing.lines() {
                        let name = line.trim();
                        if !name.is_empty() && !name.starts_with('#') {
                            lastnames.insert(name.to_string());
                        }
                    }
                }
            }

            let first_content: Vec<&str> = firstnames.iter().map(|s| s.as_str()).collect();
            let last_content: Vec<&str> = lastnames.iter().map(|s| s.as_str()).collect();

            fs::write(&first_path, first_content.join("\n") + "\n")?;
            fs::write(&last_path, last_content.join("\n") + "\n")?;

            eprintln!(
                "Updated: {} firstnames, {} lastnames ({})",
                firstnames.len(),
                lastnames.len(),
                if replace { "replaced" } else { "merged" },
            );
            eprintln!("  {}", first_path.display());
            eprintln!("  {}", last_path.display());
        }
        #[cfg(feature = "proxy")]
        Some(Commands::Api { port }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(anon_pii::api::run(port))?;
        }
        #[cfg(feature = "proxy")]
        Some(Commands::Ui {
            port,
            persist_mapping,
        }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(anon_pii::ui::run(port, persist_mapping))?;
        }
        #[cfg(feature = "proxy")]
        Some(Commands::Proxy {
            port,
            upstream,
            threshold,
            session_dir,
            persist_mapping,
            provider,
        }) => {
            let session_dir = match session_dir {
                Some(dir) => {
                    if !persist_mapping {
                        eprintln!(
                            "Warning: --session-dir is ignored unless --persist-mapping is enabled"
                        );
                    }
                    dir
                }
                None => {
                    let suffix = anon_pii::mapping::crypto_random_hex(8);
                    std::env::temp_dir().join(format!("anon-proxy-{suffix}"))
                }
            };

            let provider: proxy::Provider = provider
                .parse()
                .map_err(|e: String| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            let state = Arc::new(
                proxy::ProxyState::new(upstream, threshold, session_dir, provider)
                    .with_mapping_persistence(persist_mapping),
            );

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(proxy::run(state, port))?;
        }
        #[cfg(feature = "image")]
        Some(Commands::Image {
            input,
            output,
            threshold,
            fill_color,
            padding,
        }) => {
            // 1. OCR: extract words with bounding boxes
            let words = match anon_pii::image_redact::ocr::extract_words(&input, "eng") {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };

            if words.is_empty() {
                eprintln!("No text detected in image, copying as-is");
                if let Err(e) =
                    anon_pii::image_redact::redact::redact_image(&input, &output, &[], &fill_color)
                {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
                return Ok(());
            }

            // 2. Hybrid OCR: full-page text aligned with word boxes
            let full_text = anon_pii::image_redact::ocr::extract_text(&input, "eng");
            let reconstructed =
                anon_pii::image_redact::ocr::try_hybrid_reconstruct(full_text, &words);

            // 3. Run PII detection on extracted text
            let mut anonymizer = Anonymizer::new(threshold);
            let detections = anonymizer.analyze(&reconstructed.text);

            // 4. Map text detections to pixel regions
            let regions = anon_pii::image_redact::region::map_detections(
                &words,
                &reconstructed,
                &detections,
                padding,
            );

            // 5. Render redaction
            if let Err(e) =
                anon_pii::image_redact::redact::redact_image(&input, &output, &regions, &fill_color)
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }

            eprintln!(
                "Redacted {} region(s) → {}",
                regions.len(),
                output.display()
            );
        }
        #[cfg(feature = "pdf")]
        Some(Commands::Pdf {
            input,
            output,
            threshold,
            fill_color,
            padding,
            visual_mask_only,
        }) => {
            // 1. Extract words with bounding boxes from PDF
            let words = match anon_pii::pdf_redact::extract::extract_words(&input) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };

            if words.is_empty() {
                eprintln!("No text detected in PDF, copying as-is without redaction");
                let result = if visual_mask_only {
                    anon_pii::pdf_redact::redact::visual_mask_pdf(&input, &output, &[], &fill_color)
                } else {
                    anon_pii::pdf_redact::redact::redact_pdf(&input, &output, &[], &fill_color)
                };
                if let Err(e) = result {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
                if visual_mask_only {
                    eprintln!("Visually masked 0 region(s) → {}", output.display());
                } else {
                    eprintln!("Redacted 0 region(s) → {}", output.display());
                }
                return Ok(());
            }

            // 2. Reconstruct text with byte-span mapping
            let reconstructed = anon_pii::pdf_redact::extract::reconstruct_text(&words);

            // 3. Run PII detection on reconstructed text
            let mut anonymizer = Anonymizer::new(threshold);
            let detections = anonymizer.analyze(&reconstructed.text);

            // 4. Map text detections to PDF page-coordinate regions
            let regions = anon_pii::pdf_redact::region::map_detections(
                &words,
                &reconstructed,
                &detections,
                padding,
            );

            if !visual_mask_only && regions.len() != detections.len() {
                eprintln!(
                    "Error: one or more detected PDF spans could not be mapped to removable text; rerun with --visual-mask-only to allow overlay-only masking"
                );
                std::process::exit(1);
            }

            // 5. Render redaction or explicit visual masking
            let result = if visual_mask_only {
                anon_pii::pdf_redact::redact::visual_mask_pdf(
                    &input,
                    &output,
                    &regions,
                    &fill_color,
                )
            } else {
                anon_pii::pdf_redact::redact::redact_pdf(&input, &output, &regions, &fill_color)
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }

            if visual_mask_only {
                eprintln!(
                    "Visually masked {} region(s) → {}",
                    regions.len(),
                    output.display()
                );
            } else {
                eprintln!(
                    "Redacted {} region(s) → {}",
                    regions.len(),
                    output.display()
                );
            }
        }
        Some(Commands::ListEntities) => {
            // Load custom patterns from config if provided
            let custom_config = if let Some(ref config_path) = cli.config {
                match RecognizerConfigFile::load(config_path) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            eprintln!("{}", "Supported entity types:".bold());
            eprintln!();

            let mut seen = std::collections::HashSet::new();

            // Calculate max type width including custom patterns
            let mut type_width = PATTERNS
                .iter()
                .map(|p| p.entity_type.len())
                .max()
                .unwrap_or(10);
            if let Some(ref config) = custom_config {
                for r in &config.recognizers {
                    type_width = type_width.max(r.entity_type.len());
                }
            }

            // Print built-in patterns
            for p in PATTERNS {
                if seen.insert(p.entity_type) {
                    // Check context across all patterns for this entity type
                    let has_required = PATTERNS
                        .iter()
                        .filter(|pp| pp.entity_type == p.entity_type)
                        .any(|pp| pp.context_required && !pp.context_keywords.is_empty());
                    let has_boost = PATTERNS
                        .iter()
                        .filter(|pp| pp.entity_type == p.entity_type)
                        .any(|pp| !pp.context_required && !pp.context_keywords.is_empty());

                    let context = if has_required {
                        " (context-aware)".dimmed().to_string()
                    } else if has_boost {
                        " (context-boosted)".dimmed().to_string()
                    } else {
                        String::new()
                    };
                    eprintln!(
                        "  {:<tw$}  {}{}",
                        p.entity_type.green(),
                        p.name,
                        context,
                        tw = type_width
                    );
                }
            }

            // Print custom patterns from config
            if let Some(ref config) = custom_config {
                for r in &config.recognizers {
                    if seen.insert(r.entity_type.as_str()) {
                        let context = if r.context_required && !r.context_keywords.is_empty() {
                            " (context-aware)".dimmed().to_string()
                        } else if !r.context_required && !r.context_keywords.is_empty() {
                            " (context-boosted)".dimmed().to_string()
                        } else {
                            String::new()
                        };
                        eprintln!(
                            "  {:<tw$}  {} [custom]{}",
                            r.entity_type.green(),
                            r.name,
                            context,
                            tw = type_width
                        );
                    }
                }
            }

            #[cfg(any(feature = "ner", feature = "ner-lite"))]
            {
                let backend = if cfg!(feature = "ner") {
                    "ML"
                } else {
                    "heuristic"
                };
                eprintln!(
                    "  {:<tw$}  NER-based person detection ({backend})",
                    "PERSON".green(),
                    tw = type_width
                );
            }
        }
        None => {
            if cli.input.is_none() && io::stdin().is_terminal() {
                eprintln!("No input provided. Use --help for usage.");
                std::process::exit(1);
            }

            if cli.copy && !cli.share {
                eprintln!("Error: --copy requires --share");
                std::process::exit(2);
            }
            if cli.share && (cli.include_mapping || cli.mapping_stderr) {
                eprintln!(
                    "Error: --share refuses to output mapping data (PII). Remove --include-mapping/--mapping-stderr."
                );
                std::process::exit(2);
            }

            let content = read_input(cli.input.as_ref())?;

            // Empty input short-circuit (match Python behavior)
            if content.trim().is_empty() {
                write_output(cli.output.as_ref(), &content)?;
                return Ok(());
            }

            let mut anonymizer = Anonymizer::new(cli.threshold);

            // Load custom recognizers from config file if provided
            if let Some(ref config_path) = cli.config {
                match RecognizerConfigFile::load(config_path) {
                    Ok(config) => {
                        anonymizer.add_custom_patterns(&config);
                        if cli.verbose {
                            eprintln!(
                                "Loaded {} custom recognizer(s) from {}",
                                config.recognizers.len(),
                                config_path.display()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            anonymizer.context_boost = cli.context_boost.clamp(0.0, 1.0);
            anonymizer.min_score_with_context = cli.min_score_with_context.clamp(0.0, 1.0);
            anonymizer.operator = cli.operator;
            anonymizer.mask_config = MaskConfig {
                mask_char: cli.mask_char,
                fixed_count: cli.mask_count,
                from_end: cli.mask_from_end,
            };
            anonymizer.hash_algo = cli.hash_algo;
            if cli.operator == Operator::Encrypt {
                let hex = cli.encrypt_key.as_deref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--encrypt-key is required when using --operator encrypt",
                    )
                })?;
                let key = parse_encrypt_key(hex)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                anonymizer.encrypt_key = Some(key);
            }
            if cli.operator == Operator::Custom {
                let fmt = cli.replace_with.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--replace-with is required when using --operator custom",
                    )
                })?;
                anonymizer.replace_with = Some(fmt);
            }

            // Wire up NER detector if requested (ML + heuristic combined)
            #[cfg(feature = "ner")]
            if cli.ner {
                let config = anon_pii::ner::NerConfig::default();
                let heuristic = anon_pii::ner::heuristic::HeuristicNerDetector::new();
                // ort panics if libonnxruntime is not found; catch that gracefully
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    anon_pii::ner::ml::MlNerDetector::new(&config)
                })) {
                    Ok(Ok(ml_detector)) => {
                        let combined = anon_pii::ner::CombinedNerDetector::new(vec![
                            Box::new(ml_detector),
                            Box::new(heuristic),
                        ]);
                        anonymizer.set_ner_detector(Box::new(combined));
                        if cli.verbose {
                            eprintln!("NER: ML + heuristic backend enabled");
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("Warning: ML NER init failed: {e}");
                        eprintln!("Hint: run `anon-pii download-model` first");
                        // Fall back to heuristic only
                        anonymizer.set_ner_detector(Box::new(heuristic));
                        if cli.verbose {
                            eprintln!("NER: falling back to heuristic backend");
                        }
                    }
                    Err(_) => {
                        eprintln!("Warning: ONNX Runtime not found.");
                        eprintln!("Install it:  brew install onnxruntime");
                        eprintln!(
                            "Then set:    export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib"
                        );
                        // Fall back to heuristic only
                        anonymizer.set_ner_detector(Box::new(heuristic));
                        if cli.verbose {
                            eprintln!("NER: falling back to heuristic backend");
                        }
                    }
                }
            }
            #[cfg(all(feature = "ner-lite", not(feature = "ner")))]
            if cli.ner {
                let detector = anon_pii::ner::heuristic::HeuristicNerDetector::new();
                anonymizer.set_ner_detector(Box::new(detector));
                if cli.verbose {
                    eprintln!("NER: heuristic backend enabled");
                }
            }

            // Determine format and process
            let (parsed_json, format_name) = match cli.format {
                Format::Json => match serde_json::from_str::<serde_json::Value>(content.trim()) {
                    Ok(v) => (Some(v), "json"),
                    Err(e) => {
                        eprintln!("Error: invalid JSON input: {e}");
                        eprintln!("Hint: use --format text to force text mode");
                        std::process::exit(1);
                    }
                },
                Format::Auto => match detect_format(&content) {
                    DetectedFormat::Json(v) => (Some(v), "json"),
                    DetectedFormat::Sql => (None, "sql"),
                    DetectedFormat::Csv => (None, "csv"),
                    DetectedFormat::Text => (None, "text"),
                },
                Format::Text => (None, "text"),
                Format::Sql => (None, "sql"),
                Format::Csv => (None, "csv"),
                #[cfg(feature = "xlsx")]
                Format::Xlsx => {
                    eprintln!("Error: XLSX parsing not yet implemented");
                    eprintln!("Hint: use --format csv to export to CSV first");
                    std::process::exit(1);
                }
            };

            let (result, detections) = if let Some(parsed) = parsed_json {
                let indent = detect_json_indent(&content);
                let (anon_value, dets) = anonymizer.anonymize_json_value(&parsed);

                let indent_bytes = b" ".repeat(indent);
                let formatter = serde_json::ser::PrettyFormatter::with_indent(&indent_bytes);
                let mut buf = Vec::new();
                let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
                anon_value.serialize(&mut ser).unwrap();
                let json_str = String::from_utf8(buf).unwrap();

                (format!("{}\n", json_str), dets)
            } else if format_name == "csv" {
                anonymizer.anonymize_csv(&content)
            } else if format_name == "sql" {
                anonymizer.anonymize_sql(&content)
            } else {
                // Text format: use batched processing when NER is enabled
                #[cfg(any(feature = "ner", feature = "ner-lite"))]
                if cli.ner && cli.batch_size > 0 {
                    process_text_batched(&mut anonymizer, &content, cli.batch_size)
                } else {
                    anonymizer.anonymize_text(&content)
                }
                #[cfg(not(any(feature = "ner", feature = "ner-lite")))]
                {
                    anonymizer.anonymize_text(&content)
                }
            };

            // Handle --include-mapping: append mapping as comment at end
            let final_output = if cli.include_mapping {
                eprintln!("Warning: --include-mapping embeds original PII values in the output");
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                format!("{}\n\n/* MAPPING:\n{}\n*/", result.trim_end(), mapping_json)
            } else {
                result
            };

            if cli.share {
                let share_md = render_share_markdown(&final_output, &detections, format_name);
                let mut copy_ok = false;
                if cli.copy {
                    match copy_to_clipboard_best_effort(&share_md) {
                        Ok(_) => {
                            copy_ok = true;
                            eprintln!("Copied share snippet to clipboard.");
                        }
                        Err(e) => {
                            eprintln!("Warning: could not copy to clipboard: {e}");
                        }
                    }
                }

                write_output(cli.output.as_ref(), &share_md)?;

                let (unique_count, by_type) = summarize_detections(&detections);
                let props = json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "format": format_name,
                    "detections_unique": unique_count,
                    "entity_types": by_type.len(),
                    "copy_requested": cli.copy,
                    "copy_succeeded": copy_ok,
                });
                append_share_event("share_generated", props.clone());
                if copy_ok {
                    append_share_event("share_copied", props);
                }
            } else {
                write_output(cli.output.as_ref(), &final_output)?;
            }

            // Save mapping file (contains original PII — restrict permissions)
            let mapping_path = cli.mapping.unwrap_or_else(default_mapping_path);
            if let Some(parent) = mapping_path.parent() {
                create_private_dir(parent)?;
            }
            let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
            write_mapping_file(&mapping_path, &mapping_json)?;
            if cli.verbose {
                eprintln!("Mapping saved to {:?}", mapping_path);
            }

            // Output mapping to stderr
            if cli.mapping_stderr {
                eprintln!("WARNING: mapping output contains original PII values in cleartext");
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                eprintln!("{}", mapping_json);
            }

            // Verbose detection table
            if cli.verbose {
                print_detections(&detections);
                eprintln!(
                    "  {} entities detected (format: {}, language: {})",
                    detections.len().to_string().bold(),
                    format_name,
                    cli.language,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mapping_dir_uses_anon_pii() {
        // The default mapping directory should be ~/.anon-pii/ (not ~/.anon/)
        // to match the package rename from #144
        let dir = default_mapping_dir();
        let dir_name = dir.file_name().unwrap().to_str().unwrap();
        assert_eq!(dir_name, ".anon-pii", "config dir should be .anon-pii");
    }

    #[test]
    fn test_default_mapping_path_uses_anon_pii() {
        // The default mapping path should be ~/.anon-pii/mapping.json
        let path = default_mapping_path();
        let components: Vec<_> = path.components().collect();
        let dir_component = components[components.len() - 2];
        assert!(
            dir_component.as_os_str().to_str().unwrap() == ".anon-pii",
            "mapping path should be under .anon-pii/"
        );
    }

    #[test]
    fn test_write_mapping_file_creates_new() {
        let dir = std::env::temp_dir().join("anon-test-toctou-new");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        write_mapping_file(&path, r#"{"test": true}"#).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), r#"{"test": true}"#);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_mapping_file_overwrites_existing() {
        let dir = std::env::temp_dir().join("anon-test-toctou-overwrite");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        fs::write(&path, "old content").unwrap();

        write_mapping_file(&path, "new content").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_mapping_file_replaces_symlink_atomically() {
        use std::os::unix::fs as unix_fs;

        // The atomic rename pattern replaces the symlink directory entry
        // itself rather than following it. Verify the symlink is gone
        // and the file contains the correct content.
        let dir = std::env::temp_dir().join("anon-test-toctou-symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let target = dir.join("attacker-controlled.txt");
        fs::write(&target, "attacker file").unwrap();

        let path = dir.join("mapping.json");
        unix_fs::symlink(&target, &path).unwrap();
        assert!(path.is_symlink());

        // write_mapping_file should replace the symlink with a regular file
        write_mapping_file(&path, "safe content").unwrap();

        // The path should now be a regular file, not a symlink
        assert!(!path.is_symlink());
        assert_eq!(fs::read_to_string(&path).unwrap(), "safe content");

        // The attacker's file should NOT have been modified
        assert_eq!(fs::read_to_string(&target).unwrap(), "attacker file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mask_pii_long_value() {
        let masked = mask_pii("john@example.com");
        assert_eq!(masked, "j***m");
        assert!(!masked.contains("@"));
        assert!(!masked.contains("example"));
    }

    #[test]
    fn test_mask_pii_short_value() {
        assert_eq!(mask_pii("ab"), "**");
        assert_eq!(mask_pii("a"), "*");
    }

    #[test]
    fn test_mask_pii_three_chars() {
        let masked = mask_pii("abc");
        assert_eq!(masked, "a***c");
    }

    #[test]
    fn test_render_share_markdown_includes_code_fence_and_summary() {
        let dets = vec![
            Detection {
                entity_type: std::borrow::Cow::Borrowed("EMAIL_ADDRESS"),
                original: "john@example.com".to_string(),
                start: 0,
                end: 1,
                score: 0.9,
            },
            // duplicate (should be deduped in summary)
            Detection {
                entity_type: std::borrow::Cow::Borrowed("EMAIL_ADDRESS"),
                original: "john@example.com".to_string(),
                start: 2,
                end: 3,
                score: 0.9,
            },
            Detection {
                entity_type: std::borrow::Cow::Borrowed("IP_ADDRESS"),
                original: "127.0.0.1".to_string(),
                start: 4,
                end: 5,
                score: 0.9,
            },
        ];

        let md = render_share_markdown("{\"email\":\"[EMAIL_ADDRESS_a1b2c3d4]\"}\n", &dets, "json");
        assert!(md.contains("Anonymized with `anon-pii`."));
        assert!(md.contains("Detected 2 unique entities across 2 types"));
        assert!(md.contains("```json"));
        assert!(md.contains("{\"email\":\"[EMAIL_ADDRESS_a1b2c3d4]\"}"));
        assert!(md.trim_end().ends_with("```"));
    }

    #[test]
    fn test_choose_markdown_fence_handles_backticks_in_content() {
        let content = "line1\n```\nline3\n";
        let fence = choose_markdown_fence(content);
        assert!(fence.len() >= 4);
    }

    #[test]
    fn test_default_session_dir_has_random_suffix() {
        // Simulate what the proxy command does: generate a random session dir name
        let suffix = anon_pii::mapping::crypto_random_hex(8);
        let dir = std::env::temp_dir().join(format!("anon-proxy-{suffix}"));
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("anon-proxy-"),
            "dir name should start with anon-proxy-"
        );
        // 8 bytes = 16 hex chars
        let hex_part = &name["anon-proxy-".len()..];
        assert_eq!(hex_part.len(), 16, "random suffix should be 16 hex chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_default_session_dir_is_unique() {
        let dirs: std::collections::HashSet<String> = (0..50)
            .map(|_| {
                let suffix = anon_pii::mapping::crypto_random_hex(8);
                format!("anon-proxy-{suffix}")
            })
            .collect();
        assert!(
            dirs.len() >= 48,
            "50 generated dirs should be nearly all unique"
        );
    }

    // ─── PDF subcommand CLI tests ────────────────────────────────────────────────

    #[cfg(feature = "pdf")]
    mod pdf_cli_tests {
        use super::*;
        use clap::CommandFactory;
        use std::process::Command;

        fn create_test_pdf(path: &Path) {
            use lopdf::content::{Content, Operation};
            use lopdf::{Document, Object, Stream, dictionary};

            let mut doc = Document::with_version("1.5");

            let pages_id = doc.new_object_id();
            let font_id = doc.add_object(dictionary! {
                "Type" => "Font",
                "Subtype" => "Type1",
                "BaseFont" => "Courier",
            });
            let resources_id = doc.add_object(dictionary! {
                "Font" => dictionary! {
                    "F1" => font_id,
                },
            });

            let page1_content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![72.into(), 720.into()]),
                    Operation::new("Tj", vec![Object::string_literal("Contact Information")]),
                    Operation::new("Td", vec![0.into(), (-20).into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal("Email: john.smith@example.com")],
                    ),
                    Operation::new("Td", vec![0.into(), (-20).into()]),
                    Operation::new("Tj", vec![Object::string_literal("Phone: +1-555-123-4567")]),
                    Operation::new("ET", vec![]),
                ],
            };

            let content1_id =
                doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));

            let page1_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content1_id,
            });

            let pages = dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page1_id)],
                "Count" => 1,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            };
            doc.objects.insert(pages_id, Object::Dictionary(pages));

            let catalog_id = doc.add_object(dictionary! {
                "Type" => "Catalog",
                "Pages" => pages_id,
            });
            doc.trailer.set("Root", catalog_id);

            doc.save(path).expect("failed to save test PDF");
        }

        fn create_multipage_pdf(path: &Path) {
            use lopdf::content::{Content, Operation};
            use lopdf::{Document, Object, Stream, dictionary};

            let mut doc = Document::with_version("1.5");

            let pages_id = doc.new_object_id();
            let font_id = doc.add_object(dictionary! {
                "Type" => "Font",
                "Subtype" => "Type1",
                "BaseFont" => "Courier",
            });
            let resources_id = doc.add_object(dictionary! {
                "Font" => dictionary! {
                    "F1" => font_id,
                },
            });

            let page1_content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![72.into(), 720.into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal("Page 1: john.smith@example.com")],
                    ),
                    Operation::new("ET", vec![]),
                ],
            };

            let page2_content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![72.into(), 720.into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal("Page 2: IP 192.168.1.100")],
                    ),
                    Operation::new("ET", vec![]),
                ],
            };

            let content1_id =
                doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));
            let content2_id =
                doc.add_object(Stream::new(dictionary! {}, page2_content.encode().unwrap()));

            let page1_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content1_id,
            });
            let page2_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content2_id,
            });

            let pages = dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page1_id), Object::Reference(page2_id)],
                "Count" => 2,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            };
            doc.objects.insert(pages_id, Object::Dictionary(pages));

            let catalog_id = doc.add_object(dictionary! {
                "Type" => "Catalog",
                "Pages" => pages_id,
            });
            doc.trailer.set("Root", catalog_id);

            doc.save(path).expect("failed to save test PDF");
        }

        fn create_empty_pdf(path: &Path) {
            use lopdf::{Document, Object, dictionary};

            let mut doc = Document::with_version("1.5");

            let pages_id = doc.new_object_id();

            let page1_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
            });

            let pages = dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page1_id)],
                "Count" => 1,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            };
            doc.objects.insert(pages_id, Object::Dictionary(pages));

            let catalog_id = doc.add_object(dictionary! {
                "Type" => "Catalog",
                "Pages" => pages_id,
            });
            doc.trailer.set("Root", catalog_id);

            doc.save(path).expect("failed to save test PDF");
        }

        fn create_mixed_pii_pdf(path: &Path) {
            use lopdf::content::{Content, Operation};
            use lopdf::{Document, Object, Stream, dictionary};

            let mut doc = Document::with_version("1.5");

            let pages_id = doc.new_object_id();
            let font_id = doc.add_object(dictionary! {
                "Type" => "Font",
                "Subtype" => "Type1",
                "BaseFont" => "Courier",
            });
            let resources_id = doc.add_object(dictionary! {
                "Font" => dictionary! {
                    "F1" => font_id,
                },
            });

            let page1_content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![72.into(), 720.into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal("Email: john.doe@example.com")],
                    ),
                    Operation::new("Td", vec![0.into(), (-20).into()]),
                    Operation::new("Tj", vec![Object::string_literal("Phone: +1-555-123-4567")]),
                    Operation::new("Td", vec![0.into(), (-20).into()]),
                    Operation::new("Tj", vec![Object::string_literal("IP: 192.168.1.100")]),
                    Operation::new("Td", vec![0.into(), (-20).into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal("Credit card: 4532015112830366")],
                    ),
                    Operation::new("ET", vec![]),
                ],
            };

            let content1_id =
                doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));

            let page1_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content1_id,
            });

            let pages = dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page1_id)],
                "Count" => 1,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            };
            doc.objects.insert(pages_id, Object::Dictionary(pages));

            let catalog_id = doc.add_object(dictionary! {
                "Type" => "Catalog",
                "Pages" => pages_id,
            });
            doc.trailer.set("Root", catalog_id);

            doc.save(path).expect("failed to save test PDF");
        }

        #[test]
        fn test_pdf_cli_help_defaults_to_destructive_redaction_with_visual_mask_option() {
            let mut cmd = Cli::command();
            let pdf = cmd
                .find_subcommand_mut("pdf")
                .expect("pdf subcommand should be available with pdf feature");
            let help = pdf.render_long_help().to_string();

            assert!(
                help.contains("destructive"),
                "pdf help should describe the default destructive redaction mode:\n{help}"
            );
            assert!(
                help.contains("--visual-mask-only"),
                "pdf help should expose the explicit visual masking escape hatch:\n{help}"
            );
        }

        fn test_dir(name: &str) -> PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("anon_pdf_cli_test_{}_{name}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn test_pdf_cli_single_page() {
            let dir = test_dir("single_page");
            let input = dir.join("input.pdf");
            let output = dir.join("output.pdf");
            create_test_pdf(&input);

            let binary = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("anon-pii");

            // Skip if binary not built
            if !binary.exists() {
                eprintln!("Skipping: binary not found at {:?}", binary);
                return;
            }

            let result = Command::new(&binary)
                .args([
                    "pdf",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                ])
                .output()
                .expect("failed to execute command");

            assert!(
                result.status.success(),
                "command should succeed: {:?}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(output.exists(), "output PDF should be created");

            // Verify stderr reports visually masked regions
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(
                stderr.contains("Visually masked") || stderr.contains("region"),
                "stderr should report visual masking: {}",
                stderr
            );

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn test_pdf_cli_multipage() {
            let dir = test_dir("multipage");
            let input = dir.join("input.pdf");
            let output = dir.join("output.pdf");
            create_multipage_pdf(&input);

            let binary = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("anon-pii");

            if !binary.exists() {
                eprintln!("Skipping: binary not found");
                return;
            }

            let result = Command::new(&binary)
                .args([
                    "pdf",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                ])
                .output()
                .expect("failed to execute command");

            assert!(
                result.status.success(),
                "command should succeed: {:?}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(output.exists(), "output PDF should be created");

            // Verify the output is a valid PDF with same page count
            let doc = lopdf::Document::load(&output).expect("output should be valid PDF");
            assert_eq!(doc.get_pages().len(), 2, "should preserve page count");

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn test_pdf_cli_no_text() {
            let dir = test_dir("no_text");
            let input = dir.join("input.pdf");
            let output = dir.join("output.pdf");
            create_empty_pdf(&input);

            let binary = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("anon-pii");

            if !binary.exists() {
                eprintln!("Skipping: binary not found");
                return;
            }

            let result = Command::new(&binary)
                .args([
                    "pdf",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                ])
                .output()
                .expect("failed to execute command");

            assert!(
                result.status.success(),
                "command should succeed even with empty PDF"
            );
            assert!(output.exists(), "output PDF should be created");

            // Verify stderr indicates no PII or 0 regions
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(
                stderr.contains("0 region")
                    || stderr.contains("No text")
                    || stderr.contains("copying"),
                "stderr should indicate no PII found: {}",
                stderr
            );

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn test_pdf_cli_mixed_pii() {
            let dir = test_dir("mixed_pii");
            let input = dir.join("input.pdf");
            let output = dir.join("output.pdf");
            create_mixed_pii_pdf(&input);

            let binary = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("anon-pii");

            if !binary.exists() {
                eprintln!("Skipping: binary not found");
                return;
            }

            let result = Command::new(&binary)
                .args([
                    "pdf",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                    "--threshold",
                    "0.5",
                    "--fill-color",
                    "black",
                    "--padding",
                    "2",
                ])
                .output()
                .expect("failed to execute command");

            assert!(
                result.status.success(),
                "command should succeed: {:?}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(output.exists(), "output PDF should be created");

            let redacted_text = anon_pii::pdf_redact::extract::reconstruct_text(
                &anon_pii::pdf_redact::extract::extract_words(&output).unwrap(),
            )
            .text;
            for original in [
                "john.doe@example.com",
                "+1-555-123-4567",
                "192.168.1.100",
                "4532015112830366",
            ] {
                assert!(
                    !redacted_text.contains(original),
                    "redacted PDF output should not expose {original}: {redacted_text}"
                );
            }

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn test_pdf_cli_custom_options() {
            let dir = test_dir("custom_options");
            let input = dir.join("input.pdf");
            let output = dir.join("output.pdf");
            create_test_pdf(&input);

            let binary = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("anon-pii");

            if !binary.exists() {
                eprintln!("Skipping: binary not found");
                return;
            }

            let result = Command::new(&binary)
                .args([
                    "pdf",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                    "--threshold",
                    "0.7",
                    "--fill-color",
                    "#FF0000",
                    "--padding",
                    "5",
                ])
                .output()
                .expect("failed to execute command");

            assert!(
                result.status.success(),
                "command should succeed with custom options"
            );
            assert!(output.exists(), "output PDF should be created");

            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_create_dir_rejects_symlink() {
        use std::os::unix::fs as unix_fs;
        let base = std::env::temp_dir().join("anon-test-symlink-dir");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let target = base.join("real-dir");
        fs::create_dir_all(&target).unwrap();

        let symlink_path = base.join("symlink-dir");
        unix_fs::symlink(&target, &symlink_path).unwrap();

        // create_dir should fail because the path already exists (as a symlink)
        let result = fs::create_dir(&symlink_path);
        assert!(result.is_err(), "create_dir should reject existing symlink");

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_mapping_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("anon-test-toctou-perms");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        write_mapping_file(&path, "secret PII").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "mapping file should be owner-only (0o600), got {:o}",
            mode
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ─── Batch processing tests ─────────────────────────────────────────────────

    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    mod batch_cli_tests {
        use anon_pii::cli::Cli;
        use clap::Parser;

        #[test]
        fn test_batch_size_flag_exists() {
            // Verify that the --batch-size flag is recognized
            let cli = Cli::try_parse_from(["anon-pii", "--ner", "--batch-size", "64"]);
            assert!(
                cli.is_ok(),
                "CLI should accept --batch-size flag: {:?}",
                cli.err()
            );
            let cli = cli.unwrap();
            assert_eq!(cli.batch_size, 64);
        }

        #[test]
        fn test_batch_size_default_value() {
            // Default batch size should be 32
            let cli = Cli::parse_from(["anon-pii", "--ner"]);
            assert_eq!(cli.batch_size, 32, "Default batch size should be 32");
        }

        #[test]
        fn test_batch_size_zero_disables_batching() {
            // --batch-size 0 should disable batching (process line by line)
            let cli = Cli::parse_from(["anon-pii", "--ner", "--batch-size", "0"]);
            assert_eq!(cli.batch_size, 0);
        }
    }

    #[test]
    fn test_process_text_batched_multiline() {
        // Process multiline text with batching should preserve line order
        let input = "Line1: test@example.com\nLine2: 192.168.1.1\nLine3: no PII here";
        let mut anonymizer = Anonymizer::new(0.0);

        let result = process_text_batched(&mut anonymizer, input, 2);
        let lines: Vec<&str> = result.0.lines().collect();

        assert_eq!(lines.len(), 3, "Should preserve line count");
        assert!(
            lines[0].contains("[EMAIL_ADDRESS_"),
            "Line 1 should have email token"
        );
        assert!(
            lines[1].contains("[IP_ADDRESS_"),
            "Line 2 should have IP token"
        );
        assert_eq!(lines[2], "Line3: no PII here", "Line 3 should be unchanged");
    }

    #[test]
    fn test_process_text_batched_preserves_empty_lines() {
        let input = "test@example.com\n\n192.168.1.1\n";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, _) = process_text_batched(&mut anonymizer, input, 32);

        assert!(result.contains("\n\n"), "Should preserve empty lines");
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3, "Should have 3 lines (including empty)");
    }

    #[test]
    fn test_process_text_batched_preserves_trailing_newline() {
        let input = "test@example.com\n192.168.1.1\n";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, _) = process_text_batched(&mut anonymizer, input, 32);

        assert!(result.ends_with('\n'), "Should preserve trailing newline");
    }

    #[test]
    fn test_process_text_batched_no_trailing_newline() {
        let input = "test@example.com\n192.168.1.1";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, _) = process_text_batched(&mut anonymizer, input, 32);

        assert!(!result.ends_with('\n'), "Should not add trailing newline");
    }

    #[test]
    fn test_process_text_batched_single_line() {
        let input = "Contact: test@example.com";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, detections) = process_text_batched(&mut anonymizer, input, 32);

        assert!(result.contains("[EMAIL_ADDRESS_"));
        assert!(detections.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    }

    #[test]
    fn test_process_text_batched_empty_input() {
        let input = "";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, detections) = process_text_batched(&mut anonymizer, input, 32);

        assert_eq!(result, "");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_process_text_batched_identical_to_unbatched() {
        // Batched processing should produce identical results to unbatched
        let input = "Email: alice@example.com\nIP: 10.0.0.1\nPhone: +33 6 12 34 56 78";

        let mut a1 = Anonymizer::new(0.0);
        let (_unbatched, unbatched_dets) = a1.anonymize_text(input);

        let mut a2 = Anonymizer::new(0.0);
        let (_batched, batched_dets) = process_text_batched(&mut a2, input, 2);

        // Detection counts per entity type should match
        let count_type =
            |dets: &[Detection], t: &str| dets.iter().filter(|d| d.entity_type == t).count();

        assert_eq!(
            count_type(&unbatched_dets, "EMAIL_ADDRESS"),
            count_type(&batched_dets, "EMAIL_ADDRESS"),
            "EMAIL_ADDRESS count should match"
        );
        assert_eq!(
            count_type(&unbatched_dets, "IP_ADDRESS"),
            count_type(&batched_dets, "IP_ADDRESS"),
            "IP_ADDRESS count should match"
        );
    }

    #[test]
    fn test_process_text_batched_batch_size_one() {
        // Batch size 1 should work (degrades to per-line processing)
        let input = "test@example.com\n192.168.1.1";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, detections) = process_text_batched(&mut anonymizer, input, 1);

        assert!(result.contains("[EMAIL_ADDRESS_"));
        assert!(result.contains("[IP_ADDRESS_"));
        assert_eq!(detections.len(), 2);
    }

    #[test]
    fn test_process_text_batched_large_batch_size() {
        // Batch size larger than line count should work
        let input = "test@example.com\n192.168.1.1";
        let mut anonymizer = Anonymizer::new(0.0);

        let (result, detections) = process_text_batched(&mut anonymizer, input, 1000);

        assert!(result.contains("[EMAIL_ADDRESS_"));
        assert!(result.contains("[IP_ADDRESS_"));
        assert_eq!(detections.len(), 2);
    }
}
