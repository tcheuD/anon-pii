#[path = "support/quality.rs"]
mod quality;

use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("quality report failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let check_only = match std::env::args().nth(1).as_deref() {
        None | Some("--json") => false,
        Some("--check") => true,
        Some(argument) => {
            return Err(format!(
                "unknown argument {argument:?}; expected --json or --check"
            ));
        }
    };
    if std::env::args().nth(2).is_some() {
        return Err("quality report accepts at most one argument".to_string());
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_path = root.join("testdata/quality/v1.json");
    let baseline_path = root.join("testdata/quality/v1-baseline.json");
    let (corpus, corpus_sha256) = quality::load_corpus(&corpus_path)?;
    quality::validate_corpus(&corpus)?;
    let report = quality::evaluate(&corpus, corpus_sha256);

    if check_only {
        quality::check_contract(&report)?;
        let baseline = quality::load_baseline(&baseline_path)?;
        quality::check_baseline(&report, &baseline)?;
        println!(
            "quality {}: cases={} spans={} tp={} fp={} fn={} precision_ppm={} recall_ppm={}",
            report.corpus_version,
            report.case_count,
            report.expected_span_count,
            report.metrics.tp,
            report.metrics.fp,
            report.metrics.fn_count,
            report.metrics.precision_ppm,
            report.metrics.recall_ppm
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("failed to serialize quality report: {error}"))?
        );
    }
    Ok(())
}
