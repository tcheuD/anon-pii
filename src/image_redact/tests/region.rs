use std::borrow::Cow;

use crate::detection::Detection;
use crate::image_redact::OcrWord;
use crate::image_redact::ocr::reconstruct_text;
use crate::image_redact::region::map_detections;

fn word(text: &str, x: u32, y: u32, w: u32, h: u32) -> OcrWord {
    OcrWord {
        text: text.to_string(),
        x,
        y,
        width: w,
        height: h,
        confidence: 0.95,
    }
}

fn det(entity_type: &'static str, start: usize, end: usize, score: f64) -> Detection {
    Detection {
        entity_type: Cow::Borrowed(entity_type),
        original: String::new(),
        start,
        end,
        score,
    }
}

#[test]
fn map_empty_detections() {
    let words = vec![word("hello", 10, 10, 50, 20)];
    let rt = reconstruct_text(&words);
    let regions = map_detections(&words, &rt, &[], 2);
    assert!(regions.is_empty());
}

#[test]
fn map_single_word_detection() {
    let words = vec![word("hello", 10, 20, 50, 15)];
    let rt = reconstruct_text(&words);
    // "hello" at span (0, 5)
    let detections = vec![det("EMAIL_ADDRESS", 0, 5, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 3);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].x, 7); // 10 - 3
    assert_eq!(regions[0].y, 17); // 20 - 3
    assert_eq!(regions[0].width, 56); // 50 + 2*3
    assert_eq!(regions[0].height, 21); // 15 + 2*3
}

#[test]
fn map_multi_word_detection() {
    let words = vec![word("john", 10, 20, 40, 15), word("doe", 60, 20, 30, 15)];
    let rt = reconstruct_text(&words);
    // "john doe" → spans [(0,4), (5,8)]
    let detections = vec![det("PERSON", 0, 8, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 2);
    assert_eq!(regions.len(), 1);
    // Union: min_x=10, min_y=20, max_x=90, max_y=35
    assert_eq!(regions[0].x, 8); // 10 - 2
    assert_eq!(regions[0].y, 18); // 20 - 2
    assert_eq!(regions[0].width, 84); // (90 - 10) + 2*2
    assert_eq!(regions[0].height, 19); // (35 - 20) + 2*2
}

#[test]
fn map_multi_line_detection() {
    let words = vec![
        word("first", 10, 10, 50, 15),
        word("second", 10, 100, 60, 15),
    ];
    let rt = reconstruct_text(&words);
    // "first\nsecond" → spans [(0,5), (6,12)]
    let detections = vec![det("PERSON", 0, 12, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    // Union: min_x=10, min_y=10, max_x=max(60,70)=70, max_y=max(25,115)=115
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].y, 10);
    assert_eq!(regions[0].width, 60); // 70 - 10
    assert_eq!(regions[0].height, 105); // 115 - 10
}

#[test]
fn map_partial_word_overlap() {
    let words = vec![word("hello", 10, 20, 50, 15)];
    let rt = reconstruct_text(&words);
    // Detection covers bytes 2..4 (inside "hello" span 0..5)
    let detections = vec![det("PII", 2, 4, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].y, 20);
    assert_eq!(regions[0].width, 50);
    assert_eq!(regions[0].height, 15);
}

#[test]
fn map_detection_on_space_only() {
    let words = vec![word("aaa", 10, 10, 30, 15), word("bbb", 60, 10, 30, 15)];
    let rt = reconstruct_text(&words);
    // "aaa bbb" → spans [(0,3), (4,7)]; space is byte 3
    let detections = vec![det("PII", 3, 4, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 2);
    assert!(regions.is_empty());
}

#[test]
fn map_single_char_detection() {
    let words = vec![word("test", 10, 20, 40, 15)];
    let rt = reconstruct_text(&words);
    // Detection covers just byte 1..2 ("e" inside "test")
    let detections = vec![det("PII", 1, 2, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].width, 40);
}

#[test]
fn map_full_line_detection() {
    let words = vec![
        word("the", 10, 10, 30, 15),
        word("quick", 50, 10, 50, 15),
        word("fox", 110, 10, 30, 15),
    ];
    let rt = reconstruct_text(&words);
    // "the quick fox" → spans [(0,3), (4,9), (10,13)]
    let detections = vec![det("PII", 0, 13, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    // Union: min_x=10, max_x=110+30=140 → width=130
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].width, 130);
}

#[test]
fn map_detection_at_text_boundaries() {
    let words = vec![word("start", 10, 10, 50, 15), word("end", 80, 10, 30, 15)];
    let rt = reconstruct_text(&words);
    // "start end" → spans [(0,5), (6,9)]
    let detections = vec![
        det("PII", 0, 5, 0.9), // starts at byte 0
        det("PII", 6, 9, 0.9), // ends at last byte
    ];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].width, 50);
    assert_eq!(regions[1].x, 80);
    assert_eq!(regions[1].width, 30);
}

#[test]
fn map_padding_zero() {
    let words = vec![word("hello", 10, 20, 50, 15)];
    let rt = reconstruct_text(&words);
    let detections = vec![det("PII", 0, 5, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].y, 20);
    assert_eq!(regions[0].width, 50);
    assert_eq!(regions[0].height, 15);
}

#[test]
fn map_padding_clamps_to_zero() {
    let words = vec![word("hi", 1, 2, 20, 15)];
    let rt = reconstruct_text(&words);
    let detections = vec![det("PII", 0, 2, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 5);
    assert_eq!(regions[0].x, 0); // 1.saturating_sub(5) = 0
    assert_eq!(regions[0].y, 0); // 2.saturating_sub(5) = 0
    assert_eq!(regions[0].width, 30); // 20 + 2*5
    assert_eq!(regions[0].height, 25); // 15 + 2*5
}

#[test]
fn map_multiple_detections() {
    let words = vec![word("foo", 10, 10, 30, 15), word("bar", 60, 10, 30, 15)];
    let rt = reconstruct_text(&words);
    // "foo bar" → spans [(0,3), (4,7)]
    let detections = vec![det("TYPE_A", 0, 3, 0.9), det("TYPE_B", 4, 7, 0.8)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].x, 10);
    assert_eq!(regions[0].width, 30);
    assert_eq!(regions[1].x, 60);
    assert_eq!(regions[1].width, 30);
}

#[test]
fn map_preserves_entity_type() {
    let words = vec![word("test", 10, 10, 40, 15)];
    let rt = reconstruct_text(&words);
    let detections = vec![det("EMAIL_ADDRESS", 0, 4, 0.9)];
    let regions = map_detections(&words, &rt, &detections, 0);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].entity_type, "EMAIL_ADDRESS");
}
