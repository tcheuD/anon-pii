use super::ocr::ReconstructedText;
use super::{OcrWord, RedactionRegion};
use crate::detection::Detection;

/// Map text-domain PII detections to pixel-domain redaction regions.
///
/// For each detection, finds OCR words whose byte spans overlap the detection
/// range, computes the bounding box union of those words, applies padding, and
/// emits a `RedactionRegion`. Detections with no overlapping words (e.g.
/// whitespace-only) are silently skipped.
pub fn map_detections(
    words: &[OcrWord],
    reconstructed: &ReconstructedText,
    detections: &[Detection],
    padding: u32,
) -> Vec<RedactionRegion> {
    detections
        .iter()
        .filter_map(|det| {
            let overlapping: Vec<&OcrWord> = reconstructed
                .spans
                .iter()
                .enumerate()
                .filter(|(_, &(ws, we))| ws < det.end && we > det.start)
                .map(|(i, _)| &words[i])
                .collect();

            if overlapping.is_empty() {
                return None;
            }

            let min_x = overlapping.iter().map(|w| w.x).min().unwrap();
            let min_y = overlapping.iter().map(|w| w.y).min().unwrap();
            let max_x = overlapping
                .iter()
                .map(|w| w.x.saturating_add(w.width))
                .max()
                .unwrap();
            let max_y = overlapping
                .iter()
                .map(|w| w.y.saturating_add(w.height))
                .max()
                .unwrap();

            Some(RedactionRegion {
                x: min_x.saturating_sub(padding),
                y: min_y.saturating_sub(padding),
                width: (max_x - min_x).saturating_add(padding.saturating_mul(2)),
                height: (max_y - min_y).saturating_add(padding.saturating_mul(2)),
                entity_type: det.entity_type,
            })
        })
        .collect()
}
