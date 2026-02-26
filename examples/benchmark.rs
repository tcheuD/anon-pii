use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

use anon::detection::Anonymizer;

const SIMPLE_LOG: &str = "2024-03-15 10:00:00 [INFO] User logged in successfully. IP: 192.168.1.1";

const COMPLEX_LOG: &str = r#"2024-03-15 10:20:01 [INFO] Dumping raw socket:
    Header: Auth-Token=XYZ-123
    Body: User: Alice | CC: 4111
    1111 1111 1111
    {"metadata": "{\"source\": \"partner_api\", \"raw\": \"client%40email.com\"}"}"#;

const DEFAULT_NUM_LINES: usize = 100_000;
const SIMPLE_RATIO: f64 = 0.80;

fn feature_label() -> &'static str {
    if cfg!(feature = "ner") {
        "ner (ML)"
    } else if cfg!(feature = "ner-lite") {
        "ner-lite (heuristic)"
    } else {
        "regex-only"
    }
}

/// Try to initialize NER once and report status. Returns a closure that
/// creates properly configured Anonymizer instances without repeated init.
fn ner_setup() -> Box<dyn Fn() -> Anonymizer> {
    #[cfg(feature = "ner")]
    {
        use anon::ner::{download::model_exists, ml::MlNerDetector, NerConfig};
        let config = NerConfig::default();
        if !model_exists(&config) {
            eprintln!(
                "warning: model not downloaded, run `anon download-model` for ML NER benchmark\n"
            );
            return Box::new(|| Anonymizer::new(0.0));
        }
        match std::panic::catch_unwind(|| MlNerDetector::new(&config)) {
            Ok(Ok(_)) => {
                return Box::new(move || {
                    let mut a = Anonymizer::new(0.0);
                    let cfg = NerConfig::default();
                    if let Ok(det) = MlNerDetector::new(&cfg) {
                        a.set_ner_detector(Box::new(det));
                    }
                    a
                });
            }
            Ok(Err(e)) => eprintln!("warning: ML NER unavailable ({}), falling back to regex-only\n", e),
            Err(_) => eprintln!("warning: ONNX Runtime not found, set ORT_DYLIB_PATH — falling back to regex-only\n"),
        }
        return Box::new(|| Anonymizer::new(0.0));
    }

    #[cfg(all(feature = "ner-lite", not(feature = "ner")))]
    {
        use anon::ner::heuristic::HeuristicNerDetector;
        return Box::new(|| {
            let mut a = Anonymizer::new(0.0);
            a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
            a
        });
    }

    #[allow(unreachable_code)]
    Box::new(|| Anonymizer::new(0.0))
}

struct BenchResult {
    times: Vec<Duration>,
    lines_with_detections: usize,
    entity_counts: HashMap<String, usize>,
    total_detections: usize,
}

fn bench_lines(line: &str, count: usize, make_anonymizer: &dyn Fn() -> Anonymizer) -> BenchResult {
    let mut times = Vec::with_capacity(count);
    let mut anonymizer = make_anonymizer();
    let mut lines_with_detections = 0usize;
    let mut entity_counts: HashMap<String, usize> = HashMap::new();
    let mut total_detections = 0usize;

    for _ in 0..count {
        let t0 = Instant::now();
        let (_, dets) = anonymizer.anonymize_text(line);
        times.push(t0.elapsed());

        if !dets.is_empty() {
            lines_with_detections += 1;
        }
        total_detections += dets.len();
        for d in &dets {
            *entity_counts.entry(d.entity_type.to_string()).or_insert(0) += 1;
        }
    }

    BenchResult {
        times,
        lines_with_detections,
        entity_counts,
        total_detections,
    }
}

fn main() {
    let num_lines: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NUM_LINES);
    let num_simple = (num_lines as f64 * SIMPLE_RATIO) as usize;
    let num_complex = num_lines - num_simple;

    println!(
        "anon benchmark [{}] — {} lines ({} simple / {} complex)\n",
        feature_label(),
        num_lines,
        num_simple,
        num_complex
    );

    let make_anonymizer = ner_setup();

    // Warm-up
    {
        let mut a = make_anonymizer();
        let _ = a.anonymize_text(SIMPLE_LOG);
        let _ = a.anonymize_text(COMPLEX_LOG);
    }

    let simple = bench_lines(SIMPLE_LOG, num_simple, &make_anonymizer);
    let complex = bench_lines(COMPLEX_LOG, num_complex, &make_anonymizer);

    let simple_avg = avg(&simple.times);
    let simple_p99 = percentile(&simple.times, 99.0);
    let complex_avg = avg(&complex.times);
    let complex_p99 = percentile(&complex.times, 99.0);

    let total_time: Duration = simple.times.iter().chain(complex.times.iter()).sum();
    let total_secs = total_time.as_secs_f64();
    let total_bytes = SIMPLE_LOG.len() * num_simple + COMPLEX_LOG.len() * num_complex;
    let throughput = num_lines as f64 / total_secs;
    let data_rate = total_bytes as f64 / total_secs / 1024.0 / 1024.0;
    let penalty = complex_avg.as_secs_f64() / simple_avg.as_secs_f64();

    // Merge entity counts
    let mut all_entities: HashMap<String, usize> = HashMap::new();
    for (k, v) in simple
        .entity_counts
        .iter()
        .chain(complex.entity_counts.iter())
    {
        *all_entities.entry(k.clone()).or_insert(0) += v;
    }

    println!("Performance");
    println!("{}", "-".repeat(60));
    println!("Total time:         {:.3} s", total_secs);
    println!("Throughput:         {:.0} lines/sec", throughput);
    println!("Data rate:          {:.2} MB/sec", data_rate);
    println!("{}", "-".repeat(60));
    println!(
        "Simple  — avg: {:>8.1} us  p99: {:>8.1} us",
        simple_avg.as_secs_f64() * 1e6,
        simple_p99.as_secs_f64() * 1e6
    );
    println!(
        "Complex — avg: {:>8.1} us  p99: {:>8.1} us",
        complex_avg.as_secs_f64() * 1e6,
        complex_p99.as_secs_f64() * 1e6
    );
    println!("Complexity penalty: {:.1}x", penalty);
    println!();

    println!("Detection rates");
    println!("{}", "-".repeat(60));
    println!(
        "Simple  — {}/{} lines ({:.0}%)",
        simple.lines_with_detections,
        num_simple,
        simple.lines_with_detections as f64 / num_simple as f64 * 100.0
    );
    println!(
        "Complex — {}/{} lines ({:.0}%)",
        complex.lines_with_detections,
        num_complex,
        complex.lines_with_detections as f64 / num_complex as f64 * 100.0
    );
    println!(
        "Total detections:   {}",
        simple.total_detections + complex.total_detections
    );
    println!();

    // Entity breakdown sorted by count desc
    let mut sorted_entities: Vec<_> = all_entities.into_iter().collect();
    sorted_entities.sort_by(|a, b| b.1.cmp(&a.1));
    println!("Entity breakdown (first run)");
    println!("{}", "-".repeat(60));
    // Show per-line count from first iteration only to avoid mapping dedup noise
    let mut first_simple = make_anonymizer();
    let (_, s_dets) = first_simple.anonymize_text(SIMPLE_LOG);
    let mut first_complex = make_anonymizer();
    let (_, c_dets) = first_complex.anonymize_text(COMPLEX_LOG);
    println!(
        "  Simple log:  {:?}",
        s_dets
            .iter()
            .map(|d| d.entity_type.as_ref())
            .collect::<Vec<_>>()
    );
    println!(
        "  Complex log: {:?}",
        c_dets
            .iter()
            .map(|d| d.entity_type.as_ref())
            .collect::<Vec<_>>()
    );
    println!();

    // Write cached results for update_readme
    use serde_json::json;

    let cache_path = "bench-results.json";
    let mut existing: serde_json::Value = fs::read_to_string(cache_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({"features": {}}));

    if let Some(existing_features) = existing.get_mut("features").and_then(|v| v.as_object_mut()) {
        existing_features.insert(
            feature_label().to_string(),
            json!({
                "lines_per_sec": throughput as u64,
                "simple_avg_us": format!("{:.1}", simple_avg.as_secs_f64() * 1e6),
                "complex_avg_us": format!("{:.1}", complex_avg.as_secs_f64() * 1e6),
                "penalty": format!("{:.1}", penalty),
            }),
        );
    }

    if let Ok(json_str) = serde_json::to_string_pretty(&existing) {
        let _ = fs::write(cache_path, json_str);
        eprintln!("\nBenchmark results cached to {}", cache_path);
    }

    if throughput < 5000.0 {
        println!("WARNING: Throughput under 5k lines/sec");
    } else if throughput < 50_000.0 {
        println!("OK: Moderate throughput");
    } else {
        println!("FAST: High throughput");
    }
}

fn avg(times: &[Duration]) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let sum: Duration = times.iter().sum();
    sum / times.len() as u32
}

fn percentile(times: &[Duration], pct: f64) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted = times.to_vec();
    sorted.sort();
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
