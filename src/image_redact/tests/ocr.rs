use super::*;
use crate::image_redact::ocr::{extract_words, reconstruct_text, OcrError};
use std::path::Path;

fn tesseract_available() -> bool {
    std::process::Command::new("tesseract")
        .arg("--version")
        .output()
        .is_ok()
}

// ── Unit tests (no Tesseract needed) ────────────────────────────────

#[test]
fn reconstruct_empty_words() {
    let result = reconstruct_text(&[]);
    assert!(result.text.is_empty());
    assert!(result.spans.is_empty());
}

#[test]
fn reconstruct_single_word() {
    let words = vec![OcrWord {
        text: "hello".into(),
        x: 10,
        y: 10,
        width: 50,
        height: 20,
        confidence: 0.95,
    }];
    let result = reconstruct_text(&words);
    assert_eq!(result.text, "hello");
    assert_eq!(result.spans, vec![(0, 5)]);
}

#[test]
fn reconstruct_same_line_sorted_by_x() {
    let words = vec![
        OcrWord {
            text: "world".into(),
            x: 100,
            y: 10,
            width: 50,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "hello".into(),
            x: 10,
            y: 10,
            width: 50,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    assert_eq!(result.text, "hello world");
    // spans[0] → word0 ("world"), spans[1] → word1 ("hello")
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "world");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "hello");
}

#[test]
fn reconstruct_different_lines() {
    let words = vec![
        OcrWord {
            text: "top".into(),
            x: 10,
            y: 10,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "bottom".into(),
            x: 10,
            y: 100,
            width: 60,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    assert_eq!(result.text, "top\nbottom");
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "top");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "bottom");
}

#[test]
fn reconstruct_mixed_lines_and_words() {
    let words = vec![
        OcrWord {
            text: "two".into(),
            x: 100,
            y: 50,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "hello".into(),
            x: 10,
            y: 10,
            width: 50,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "line".into(),
            x: 10,
            y: 50,
            width: 40,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "world".into(),
            x: 100,
            y: 10,
            width: 50,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    assert_eq!(result.text, "hello world\nline two");
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "two");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "hello");
    assert_eq!(&result.text[result.spans[2].0..result.spans[2].1], "line");
    assert_eq!(&result.text[result.spans[3].0..result.spans[3].1], "world");
}

#[test]
fn reconstruct_y_tolerance() {
    let words = vec![
        OcrWord {
            text: "foo".into(),
            x: 10,
            y: 10,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "bar".into(),
            x: 100,
            y: 18,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    // y diff = 8, tolerance = max(1, min(20, 20) / 2) = 10 → same line
    assert_eq!(result.text, "foo bar");
}

#[test]
fn reconstruct_unicode_byte_offsets() {
    let words = vec![
        OcrWord {
            text: "café".into(),
            x: 10,
            y: 10,
            width: 40,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "résumé".into(),
            x: 100,
            y: 10,
            width: 60,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    assert_eq!(result.text, "café résumé");
    // "café" is 5 bytes (é = 2 bytes), "résumé" is 8 bytes
    assert_eq!(result.spans[0], (0, 5));
    assert_eq!(result.spans[1], (6, 14));
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "café");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "résumé");
}

#[test]
fn reconstruct_y_tolerance_boundary_splits_line() {
    let words = vec![
        OcrWord {
            text: "aaa".into(),
            x: 10,
            y: 10,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
        OcrWord {
            text: "bbb".into(),
            x: 10,
            y: 21,
            width: 30,
            height: 20,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    // y diff = 11, tolerance = max(1, min(20, 20) / 2) = 10 → different lines
    assert_eq!(result.text, "aaa\nbbb");
}

#[test]
fn reconstruct_zero_height_words() {
    let words = vec![
        OcrWord {
            text: "a".into(),
            x: 10,
            y: 10,
            width: 10,
            height: 0,
            confidence: 0.9,
        },
        OcrWord {
            text: "b".into(),
            x: 50,
            y: 11,
            width: 10,
            height: 0,
            confidence: 0.9,
        },
    ];
    let result = reconstruct_text(&words);
    // tolerance = max(1, min(0, 0) / 2) = max(1, 0) = 1, y diff = 1 → same line
    assert_eq!(result.text, "a b");
}

// ── Input validation tests ──────────────────────────────────────────

#[test]
fn extract_words_rejects_invalid_lang() {
    let result = extract_words(Path::new("testdata/images/blank.png"), "../etc");
    assert!(matches!(result, Err(OcrError::Init(_))));
}

#[test]
fn extract_words_accepts_underscore_lang() {
    // "chi_sim" style lang codes must pass validation (Tesseract will still
    // fail if the traineddata isn't installed, but validation itself passes)
    let result = extract_words(Path::new("testdata/images/blank.png"), "chi_sim");
    // Should NOT be an Init error about invalid lang code
    match result {
        Err(OcrError::Init(msg)) => assert!(
            !msg.contains("invalid language code"),
            "underscore lang should pass validation"
        ),
        _ => {} // Ok or other error is fine
    }
}

#[test]
fn extract_words_rejects_empty_lang() {
    let result = extract_words(Path::new("testdata/images/blank.png"), "");
    assert!(matches!(result, Err(OcrError::Init(_))));
}

#[test]
fn extract_words_rejects_symlink() {
    let dir = std::env::temp_dir().join("anon-test-ocr-symlink");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("real.png");
    std::fs::copy("testdata/images/blank.png", &target).unwrap();
    let link = dir.join("link.png");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(unix)]
    {
        let result = extract_words(&link, "eng");
        assert!(matches!(result, Err(OcrError::ImageLoad(_))));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Integration tests (require Tesseract, #[ignore]) ───────────────

#[test]
#[ignore]
fn extract_words_from_email_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let words = extract_words(Path::new("testdata/images/email.png"), "eng")
        .expect("should extract words from email image");
    assert!(!words.is_empty());
    for w in &words {
        assert!(w.width > 0, "word width must be positive");
        assert!(w.height > 0, "word height must be positive");
        assert!(
            (0.0..=1.0).contains(&w.confidence),
            "confidence {} out of range",
            w.confidence
        );
    }
}

#[test]
#[ignore]
fn extract_words_from_clean_text_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let words = extract_words(Path::new("testdata/images/clean_text.png"), "eng")
        .expect("should extract words from clean text image");
    assert!(!words.is_empty());
}

#[test]
#[ignore]
fn extract_words_blank_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let words = extract_words(Path::new("testdata/images/blank.png"), "eng")
        .expect("should succeed on blank image");
    assert!(words.is_empty(), "blank image should yield no words");
}

#[test]
#[ignore]
fn extract_words_invalid_path() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let result = extract_words(Path::new("nonexistent.png"), "eng");
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), OcrError::ImageLoad(_)),
        "expected OcrError::ImageLoad for missing file"
    );
}

#[test]
#[ignore]
fn extract_words_multiline() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let words = extract_words(Path::new("testdata/images/multiline.png"), "eng")
        .expect("should extract words from multiline image");
    assert!(!words.is_empty());
    let distinct_y_values: std::collections::HashSet<u32> = words.iter().map(|w| w.y).collect();
    assert!(
        distinct_y_values.len() >= 2,
        "multiline image should have at least 2 distinct y values, got {:?}",
        distinct_y_values
    );
}
