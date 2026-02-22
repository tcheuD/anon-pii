use crate::detection::Anonymizer;
use crate::image_redact::{ocr, redact, region};
use std::path::Path;

fn tesseract_available() -> bool {
    std::process::Command::new("tesseract")
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
#[ignore]
fn e2e_email_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }

    let words = ocr::extract_words(Path::new("testdata/images/email.png"), "eng")
        .expect("OCR should succeed");
    assert!(!words.is_empty(), "should detect words in email image");

    let reconstructed = ocr::reconstruct_text(&words);
    assert!(
        reconstructed.text.contains('@'),
        "reconstructed text should contain @ from email"
    );

    let mut anonymizer = Anonymizer::new(0.5);
    let detections = anonymizer.analyze(&reconstructed.text);
    assert!(
        !detections.is_empty(),
        "should detect PII in email image text"
    );
    assert!(
        detections.iter().any(|d| d.entity_type.contains("EMAIL")),
        "should detect EMAIL entity, got: {:?}",
        detections.iter().map(|d| d.entity_type).collect::<Vec<_>>()
    );

    let regions = region::map_detections(&words, &reconstructed, &detections, 2);
    assert!(!regions.is_empty(), "should produce redaction regions");

    let dir = std::env::temp_dir().join("anon-test-e2e-email");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("redacted.png");

    redact::redact_image(
        Path::new("testdata/images/email.png"),
        &output,
        &regions,
        "black",
    )
    .expect("redact_image should succeed");

    assert!(output.exists(), "output file should exist");
    assert!(
        std::fs::metadata(&output).unwrap().len() > 0,
        "output file should be non-empty"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn e2e_clean_text_no_pii() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }

    let words = ocr::extract_words(Path::new("testdata/images/clean_text.png"), "eng")
        .expect("OCR should succeed on clean text");
    assert!(!words.is_empty(), "should detect words in clean text image");

    let reconstructed = ocr::reconstruct_text(&words);

    let mut anonymizer = Anonymizer::new(0.5);
    let detections = anonymizer.analyze(&reconstructed.text);
    assert!(
        detections.is_empty(),
        "clean text should have no PII detections, got: {:?}",
        detections
            .iter()
            .map(|d| (d.entity_type, &d.original))
            .collect::<Vec<_>>()
    );

    let regions = region::map_detections(&words, &reconstructed, &detections, 2);
    assert!(regions.is_empty(), "no detections means no regions");

    let dir = std::env::temp_dir().join("anon-test-e2e-clean");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("clean_out.png");

    redact::redact_image(
        Path::new("testdata/images/clean_text.png"),
        &output,
        &regions,
        "black",
    )
    .expect("redact_image should succeed with empty regions");

    assert!(output.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn e2e_blank_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }

    let words = ocr::extract_words(Path::new("testdata/images/blank.png"), "eng")
        .expect("OCR should succeed on blank image");
    assert!(words.is_empty(), "blank image should yield no words");

    let dir = std::env::temp_dir().join("anon-test-e2e-blank");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("blank_out.png");

    redact::redact_image(
        Path::new("testdata/images/blank.png"),
        &output,
        &[],
        "black",
    )
    .expect("redact_image should succeed on blank image");

    assert!(output.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn e2e_threshold_filtering() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }

    let words = ocr::extract_words(Path::new("testdata/images/email.png"), "eng")
        .expect("OCR should succeed");
    let reconstructed = ocr::reconstruct_text(&words);

    let mut low = Anonymizer::new(0.0);
    let low_detections = low.analyze(&reconstructed.text);

    let mut high = Anonymizer::new(1.0);
    let high_detections = high.analyze(&reconstructed.text);

    assert!(
        low_detections.len() >= high_detections.len(),
        "low threshold ({}) should find >= detections than high threshold ({})",
        low_detections.len(),
        high_detections.len()
    );
}
