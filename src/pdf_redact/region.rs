use super::extract::ReconstructedPdfText;
use super::{PdfWord, RedactionRegion};
use crate::detection::Detection;

/// Map text-domain PII detections to PDF page-coordinate redaction regions.
///
/// For each detection, finds PDF words whose byte spans overlap the detection
/// range, computes the bounding box union of those words, applies padding, and
/// emits a `RedactionRegion`. Detections with no overlapping words (e.g.
/// whitespace-only) are skipped; callers decide whether that is a hard failure.
///
/// This is the PDF equivalent of `image_redact::region::map_detections()`.
pub fn map_detections(
    words: &[PdfWord],
    reconstructed: &ReconstructedPdfText,
    detections: &[Detection],
    padding: f64,
) -> Vec<RedactionRegion> {
    detections
        .iter()
        .filter_map(|det| {
            let overlapping: Vec<&PdfWord> = reconstructed
                .spans
                .iter()
                .enumerate()
                .filter(|&(_, &(ws, we))| ws < det.end && we > det.start)
                .map(|(i, _)| &words[i])
                .collect();

            if overlapping.is_empty() {
                return None;
            }

            // All overlapping words should be on the same page in typical use,
            // but we take the first word's page for the region
            let page = overlapping[0].page;

            let min_x = overlapping
                .iter()
                .map(|w| w.x)
                .fold(f64::INFINITY, f64::min);
            let min_y = overlapping
                .iter()
                .map(|w| w.y)
                .fold(f64::INFINITY, f64::min);
            let max_x = overlapping
                .iter()
                .map(|w| w.x + w.width)
                .fold(f64::NEG_INFINITY, f64::max);
            let max_y = overlapping
                .iter()
                .map(|w| w.y + w.height)
                .fold(f64::NEG_INFINITY, f64::max);

            Some(RedactionRegion {
                page,
                x: (min_x - padding).max(0.0),
                y: (min_y - padding).max(0.0),
                width: (max_x - min_x) + padding * 2.0,
                height: (max_y - min_y) + padding * 2.0,
                entity_type: det.entity_type.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(text: &str, page: u32, x: f64, y: f64, w: f64, h: f64) -> PdfWord {
        PdfWord {
            text: text.to_string(),
            page,
            x,
            y,
            width: w,
            height: h,
        }
    }

    fn det(entity_type: &'static str, start: usize, end: usize, score: f64) -> Detection {
        Detection {
            entity_type: std::borrow::Cow::Borrowed(entity_type),
            original: String::new(),
            start,
            end,
            score,
        }
    }

    fn reconstruct(words: &[PdfWord]) -> ReconstructedPdfText {
        crate::pdf_redact::extract::reconstruct_text(words)
    }

    #[test]
    fn map_empty_detections() {
        let words = vec![word("hello", 1, 10.0, 700.0, 50.0, 12.0)];
        let rt = reconstruct(&words);
        let regions = map_detections(&words, &rt, &[], 2.0);
        assert!(regions.is_empty());
    }

    #[test]
    fn map_single_word_detection() {
        let words = vec![word("hello", 1, 10.0, 700.0, 50.0, 12.0)];
        let rt = reconstruct(&words);
        // "hello" at span (0, 5)
        let detections = vec![det("EMAIL_ADDRESS", 0, 5, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 3.0);
        assert_eq!(regions.len(), 1);
        assert!((regions[0].x - 7.0).abs() < 0.01); // 10 - 3
        assert!((regions[0].y - 697.0).abs() < 0.01); // 700 - 3
        assert!((regions[0].width - 56.0).abs() < 0.01); // 50 + 2*3
        assert!((regions[0].height - 18.0).abs() < 0.01); // 12 + 2*3
        assert_eq!(regions[0].page, 1);
    }

    #[test]
    fn map_multi_word_detection() {
        let words = vec![
            word("john", 1, 10.0, 700.0, 40.0, 12.0),
            word("doe", 1, 60.0, 700.0, 30.0, 12.0),
        ];
        let rt = reconstruct(&words);
        // "john doe" -> spans [(0,4), (5,8)]
        let detections = vec![det("PERSON", 0, 8, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 2.0);
        assert_eq!(regions.len(), 1);
        // Union: min_x=10, min_y=700, max_x=90, max_y=712
        assert!((regions[0].x - 8.0).abs() < 0.01); // 10 - 2
        assert!((regions[0].y - 698.0).abs() < 0.01); // 700 - 2
        assert!((regions[0].width - 84.0).abs() < 0.01); // (90 - 10) + 2*2
        assert!((regions[0].height - 16.0).abs() < 0.01); // (712 - 700) + 2*2
    }

    #[test]
    fn map_multipage_detections() {
        let words = vec![
            word("page1email", 1, 72.0, 700.0, 80.0, 12.0),
            word("page2phone", 2, 72.0, 700.0, 80.0, 12.0),
        ];
        let rt = reconstruct(&words);
        // "page1email\n\npage2phone"
        // spans: [(0,10), (12,22)]
        let detections = vec![
            det("EMAIL_ADDRESS", 0, 10, 0.9),
            det("PHONE_NUMBER", 12, 22, 0.9),
        ];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].page, 1);
        assert_eq!(regions[1].page, 2);
    }

    #[test]
    fn map_partial_word_overlap() {
        let words = vec![word("hello", 1, 10.0, 700.0, 50.0, 12.0)];
        let rt = reconstruct(&words);
        // Detection covers bytes 2..4 (inside "hello" span 0..5)
        let detections = vec![det("PII", 2, 4, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 1);
        assert!((regions[0].x - 10.0).abs() < 0.01);
        assert!((regions[0].y - 700.0).abs() < 0.01);
        assert!((regions[0].width - 50.0).abs() < 0.01);
        assert!((regions[0].height - 12.0).abs() < 0.01);
    }

    #[test]
    fn map_detection_on_space_only() {
        let words = vec![
            word("aaa", 1, 10.0, 700.0, 30.0, 12.0),
            word("bbb", 1, 60.0, 700.0, 30.0, 12.0),
        ];
        let rt = reconstruct(&words);
        // "aaa bbb" -> spans [(0,3), (4,7)]; space is byte 3
        let detections = vec![det("PII", 3, 4, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 2.0);
        assert!(regions.is_empty());
    }

    #[test]
    fn map_padding_zero() {
        let words = vec![word("hello", 1, 10.0, 700.0, 50.0, 12.0)];
        let rt = reconstruct(&words);
        let detections = vec![det("PII", 0, 5, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 1);
        assert!((regions[0].x - 10.0).abs() < 0.01);
        assert!((regions[0].y - 700.0).abs() < 0.01);
        assert!((regions[0].width - 50.0).abs() < 0.01);
        assert!((regions[0].height - 12.0).abs() < 0.01);
    }

    #[test]
    fn map_padding_clamps_to_zero() {
        let words = vec![word("hi", 1, 1.0, 2.0, 20.0, 12.0)];
        let rt = reconstruct(&words);
        let detections = vec![det("PII", 0, 2, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 5.0);
        assert!((regions[0].x - 0.0).abs() < 0.01); // 1 - 5 clamped to 0
        assert!((regions[0].y - 0.0).abs() < 0.01); // 2 - 5 clamped to 0
        assert!((regions[0].width - 30.0).abs() < 0.01); // 20 + 2*5
        assert!((regions[0].height - 22.0).abs() < 0.01); // 12 + 2*5
    }

    #[test]
    fn map_multiple_detections() {
        let words = vec![
            word("foo", 1, 10.0, 700.0, 30.0, 12.0),
            word("bar", 1, 60.0, 700.0, 30.0, 12.0),
        ];
        let rt = reconstruct(&words);
        // "foo bar" -> spans [(0,3), (4,7)]
        let detections = vec![det("TYPE_A", 0, 3, 0.9), det("TYPE_B", 4, 7, 0.8)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 2);
        assert!((regions[0].x - 10.0).abs() < 0.01);
        assert!((regions[0].width - 30.0).abs() < 0.01);
        assert!((regions[1].x - 60.0).abs() < 0.01);
        assert!((regions[1].width - 30.0).abs() < 0.01);
    }

    #[test]
    fn map_preserves_entity_type() {
        let words = vec![word("test", 1, 10.0, 700.0, 40.0, 12.0)];
        let rt = reconstruct(&words);
        let detections = vec![det("EMAIL_ADDRESS", 0, 4, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn map_preserves_page_number() {
        let words = vec![word("data", 3, 72.0, 700.0, 40.0, 12.0)];
        let rt = reconstruct(&words);
        let detections = vec![det("US_SSN", 0, 4, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].page, 3);
    }

    #[test]
    fn map_multi_line_same_page() {
        let words = vec![
            word("first", 1, 10.0, 700.0, 50.0, 12.0),
            word("second", 1, 10.0, 650.0, 60.0, 12.0),
        ];
        let rt = reconstruct(&words);
        // "first\nsecond" -> spans [(0,5), (6,12)]
        let detections = vec![det("PERSON", 0, 12, 0.9)];
        let regions = map_detections(&words, &rt, &detections, 0.0);
        assert_eq!(regions.len(), 1);
        // Union: min_x=10, min_y=650, max_x=max(60,70)=70, max_y=712
        assert!((regions[0].x - 10.0).abs() < 0.01);
        assert!((regions[0].y - 650.0).abs() < 0.01);
        assert!((regions[0].width - 60.0).abs() < 0.01); // 70 - 10
        assert!((regions[0].height - 62.0).abs() < 0.01); // 712 - 650
        assert_eq!(regions[0].page, 1);
    }
}
