use std::time::{Duration, Instant};

use anon::detection::Anonymizer;

const SIMPLE_LOG: &str =
    "2024-03-15 10:00:00 [INFO] User logged in successfully. IP: 192.168.1.1";

const COMPLEX_LOG: &str = r#"2024-03-15 10:20:01 [INFO] Dumping raw socket:
    Header: Auth-Token=XYZ-123
    Body: User: Alice | CC: 4111
    1111 1111 1111
    {"metadata": "{\"source\": \"partner_api\", \"raw\": \"client%40email.com\"}"}"#;

const NUM_LINES: usize = 100_000;
const SIMPLE_RATIO: f64 = 0.80;

fn main() {
    let num_simple = (NUM_LINES as f64 * SIMPLE_RATIO) as usize;
    let num_complex = NUM_LINES - num_simple;

    println!("anon benchmark — {} lines ({} simple / {} complex)\n", NUM_LINES, num_simple, num_complex);

    // Warm-up: compile regex lazily on first call
    {
        let mut a = Anonymizer::new(0.0);
        let _ = a.anonymize_text(SIMPLE_LOG);
        let _ = a.anonymize_text(COMPLEX_LOG);
    }

    // Benchmark simple logs
    let simple_times = bench_lines(SIMPLE_LOG, num_simple);
    let simple_avg = avg(&simple_times);
    let simple_p99 = percentile(&simple_times, 99.0);
    let simple_bytes: usize = SIMPLE_LOG.len() * num_simple;

    // Benchmark complex logs
    let complex_times = bench_lines(COMPLEX_LOG, num_complex);
    let complex_avg = avg(&complex_times);
    let complex_p99 = percentile(&complex_times, 99.0);
    let complex_bytes: usize = COMPLEX_LOG.len() * num_complex;

    // Combined
    let total_time: Duration = simple_times.iter().chain(complex_times.iter()).sum();
    let total_secs = total_time.as_secs_f64();
    let total_bytes = simple_bytes + complex_bytes;
    let throughput = NUM_LINES as f64 / total_secs;
    let data_rate = total_bytes as f64 / total_secs / 1024.0 / 1024.0;
    let penalty = complex_avg.as_secs_f64() / simple_avg.as_secs_f64();

    println!("Results");
    println!("{}", "-".repeat(60));
    println!("Total time:         {:.3} s", total_secs);
    println!("Throughput:         {:.0} lines/sec", throughput);
    println!("Data rate:          {:.2} MB/sec", data_rate);
    println!("{}", "-".repeat(60));
    println!("Simple  — avg: {:>8.1} us  p99: {:>8.1} us", simple_avg.as_secs_f64() * 1e6, simple_p99.as_secs_f64() * 1e6);
    println!("Complex — avg: {:>8.1} us  p99: {:>8.1} us", complex_avg.as_secs_f64() * 1e6, complex_p99.as_secs_f64() * 1e6);
    println!("Complexity penalty: {:.1}x", penalty);
    println!("{}", "-".repeat(60));

    if throughput < 5000.0 {
        println!("WARNING: Throughput under 5k lines/sec");
    } else if throughput < 50_000.0 {
        println!("OK: Moderate throughput");
    } else {
        println!("FAST: High throughput");
    }
}

fn bench_lines(line: &str, count: usize) -> Vec<Duration> {
    let mut times = Vec::with_capacity(count);
    let mut anonymizer = Anonymizer::new(0.0);
    for _ in 0..count {
        let t0 = Instant::now();
        let _ = anonymizer.anonymize_text(line);
        times.push(t0.elapsed());
    }
    times
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
