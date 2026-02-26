use super::*;
use crate::image_redact::ocr::{
    extract_text, extract_words, hybrid_reconstruct, reconstruct_text, try_hybrid_reconstruct,
    OcrError,
};
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

// ── extract_text unit tests ─────────────────────────────────────────

#[test]
fn extract_text_rejects_invalid_lang() {
    let result = extract_text(Path::new("testdata/images/blank.png"), "../etc");
    assert!(matches!(result, Err(OcrError::Init(_))));
}

#[test]
fn extract_text_rejects_empty_lang() {
    let result = extract_text(Path::new("testdata/images/blank.png"), "");
    assert!(matches!(result, Err(OcrError::Init(_))));
}

#[test]
fn extract_text_accepts_underscore_lang() {
    let result = extract_text(Path::new("testdata/images/blank.png"), "chi_sim");
    match result {
        Err(OcrError::Init(msg)) => assert!(
            !msg.contains("invalid language code"),
            "underscore lang should pass validation"
        ),
        _ => {}
    }
}

#[test]
fn extract_text_rejects_symlink() {
    let dir = std::env::temp_dir().join("anon-test-ocr-text-symlink");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("real.png");
    std::fs::copy("testdata/images/blank.png", &target).unwrap();
    let link = dir.join("link.png");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(unix)]
    {
        let result = extract_text(&link, "eng");
        assert!(matches!(result, Err(OcrError::ImageLoad(_))));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── extract_text integration tests (require Tesseract, #[ignore]) ───

#[test]
#[ignore]
fn extract_text_blank_image() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let text = extract_text(Path::new("testdata/images/blank.png"), "eng")
        .expect("should succeed on blank image");
    assert!(text.is_empty(), "blank image should yield empty text");
}

#[test]
#[ignore]
fn extract_text_invalid_path() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let result = extract_text(Path::new("nonexistent.png"), "eng");
    assert!(
        matches!(result, Err(OcrError::ImageLoad(_))),
        "expected OcrError::ImageLoad for missing file"
    );
}

#[test]
#[ignore]
fn extract_text_vs_word_concatenation() {
    if !tesseract_available() {
        eprintln!("Tesseract not available, skipping");
        return;
    }
    let path = Path::new("testdata/images/clean_text.png");
    let full_text = extract_text(path, "eng").expect("extract_text should succeed");
    let words = extract_words(path, "eng").expect("extract_words should succeed");

    let full_words: Vec<&str> = full_text.split_whitespace().collect();
    let word_texts: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();

    // Both methods should find the same number of words
    assert_eq!(
        full_words.len(),
        word_texts.len(),
        "word count mismatch: extract_text={full_words:?}, extract_words={word_texts:?}"
    );

    // Most words should match (Tesseract may produce minor differences between
    // full-page and word-level segmentation modes)
    let matching = full_words
        .iter()
        .zip(&word_texts)
        .filter(|(a, b)| a == b)
        .count();
    let ratio = matching as f64 / full_words.len().max(1) as f64;
    assert!(
        ratio >= 0.5,
        "less than 50% word match: extract_text={full_words:?}, extract_words={word_texts:?}"
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

// ── hybrid_reconstruct unit tests ───────────────────────────────────

fn make_word(text: &str, x: u32, y: u32, width: u32, height: u32) -> OcrWord {
    OcrWord {
        text: text.into(),
        x,
        y,
        width,
        height,
        confidence: 0.9,
    }
}

#[test]
fn hybrid_reconstruct_basic() {
    let words = vec![
        make_word("hello", 10, 10, 50, 20),
        make_word("world", 100, 10, 50, 20),
    ];
    let full_text = "hello world";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, "hello world");
    assert_eq!(result.spans.len(), 2);
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "hello");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "world");
}

#[test]
fn hybrid_reconstruct_multiline() {
    let words = vec![
        make_word("top", 10, 10, 30, 20),
        make_word("left", 10, 100, 40, 20),
        make_word("right", 100, 100, 50, 20),
    ];
    let full_text = "top\nleft right";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, full_text);
    assert_eq!(result.spans.len(), 3);
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "top");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "left");
    assert_eq!(&result.text[result.spans[2].0..result.spans[2].1], "right");
}

#[test]
fn hybrid_reconstruct_preserves_original_word_order() {
    // words given out of reading order (word[0]="world" is rightmost)
    let words = vec![
        make_word("world", 100, 10, 50, 20),
        make_word("hello", 10, 10, 50, 20),
    ];
    let full_text = "hello world";
    let result = hybrid_reconstruct(full_text, &words);
    // spans[0] corresponds to words[0] ("world"), spans[1] to words[1] ("hello")
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "world");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "hello");
}

#[test]
fn hybrid_reconstruct_empty_words() {
    let result = hybrid_reconstruct("some text", &[]);
    assert_eq!(result.text, "some text");
    assert!(result.spans.is_empty());
}

#[test]
fn hybrid_reconstruct_empty_text() {
    let result = hybrid_reconstruct("", &[]);
    assert!(result.text.is_empty());
    assert!(result.spans.is_empty());
}

#[test]
fn hybrid_reconstruct_more_words_than_tokens() {
    // 3 word boxes but only 2 tokens in full text — extra words get (0,0) fallback
    let words = vec![
        make_word("hello", 10, 10, 50, 20),
        make_word("beautiful", 70, 10, 90, 20),
        make_word("world", 200, 10, 50, 20),
    ];
    let full_text = "hello world";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, "hello world");
    // Must produce exactly 3 spans (one per word box)
    assert_eq!(result.spans.len(), 3);
    // Greedy positional: word[0]→token[0] "hello", word[1]→token[1] "world",
    // word[2]→fallback (0,0) since there are only 2 tokens
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "hello");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "world");
    assert_eq!(result.spans[2], (0, 0));
}

#[test]
fn hybrid_reconstruct_fewer_words_than_tokens() {
    // 2 word boxes but 3 tokens in full text — unmatched tokens are ignored
    let words = vec![
        make_word("hello", 10, 10, 50, 20),
        make_word("world", 100, 10, 50, 20),
    ];
    let full_text = "hello beautiful world";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, "hello beautiful world");
    assert_eq!(result.spans.len(), 2);
}

#[test]
fn hybrid_reconstruct_unicode() {
    let words = vec![
        make_word("café", 10, 10, 40, 20),
        make_word("résumé", 100, 10, 60, 20),
    ];
    let full_text = "café résumé";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, "café résumé");
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "café");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "résumé");
}

#[test]
fn hybrid_reconstruct_map_detections_compatible() {
    // Verify that the ReconstructedText from hybrid_reconstruct works with
    // map_detections — spans[i] must index into words[i]
    use std::borrow::Cow;

    use crate::detection::Detection;
    use crate::image_redact::region::map_detections;

    let words = vec![
        make_word("test@example.com", 10, 10, 200, 20),
        make_word("other", 10, 50, 50, 20),
    ];
    let full_text = "test@example.com\nother";
    let result = hybrid_reconstruct(full_text, &words);

    let detections = vec![Detection {
        entity_type: Cow::Borrowed("EMAIL_ADDRESS"),
        original: "test@example.com".to_string(),
        start: result.spans[0].0,
        end: result.spans[0].1,
        score: 0.95,
    }];

    let regions = map_detections(&words, &result, &detections, 0);
    assert_eq!(regions.len(), 1);
    // Region should match the bounding box of words[0]
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].y, 10);
    assert_eq!(regions[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn hybrid_reconstruct_different_whitespace() {
    // full-page text uses newline where words would be on same line
    let words = vec![
        make_word("line1", 10, 10, 50, 20),
        make_word("line2", 10, 50, 50, 20),
    ];
    let full_text = "line1\nline2";
    let result = hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, full_text);
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "line1");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "line2");
}

// ── try_hybrid_reconstruct unit tests ──────────────────────────────

#[test]
fn try_hybrid_uses_full_text_when_available() {
    let words = vec![
        make_word("hello", 0, 0, 50, 20),
        make_word("world", 60, 0, 50, 20),
    ];
    let full_text: Result<String, OcrError> = Ok("hello world".to_string());
    let result = try_hybrid_reconstruct(full_text, &words);
    assert_eq!(result.text, "hello world");
    assert_eq!(result.spans.len(), 2);
    assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "hello");
    assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "world");
}

#[test]
fn try_hybrid_falls_back_on_error() {
    let words = vec![
        make_word("hello", 0, 0, 50, 20),
        make_word("world", 60, 0, 50, 20),
    ];
    let full_text: Result<String, OcrError> = Err(OcrError::Extraction("test error".into()));
    let result = try_hybrid_reconstruct(full_text, &words);
    // Falls back to reconstruct_text: same text, valid spans
    assert_eq!(result.text, "hello world");
    assert_eq!(result.spans.len(), 2);
}

#[test]
fn try_hybrid_empty_words() {
    let full_text: Result<String, OcrError> = Ok("some text".to_string());
    let result = try_hybrid_reconstruct(full_text, &[]);
    // hybrid_reconstruct with empty words returns the full text with no spans
    assert_eq!(result.text, "some text");
    assert!(result.spans.is_empty());
}

#[test]
fn try_hybrid_empty_words_on_error() {
    let full_text: Result<String, OcrError> = Err(OcrError::Extraction("fail".into()));
    let result = try_hybrid_reconstruct(full_text, &[]);
    // reconstruct_text with empty words returns empty text
    assert_eq!(result.text, "");
    assert!(result.spans.is_empty());
}
