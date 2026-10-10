//! Automatic backend selection for the local API and proxy.

use super::{NerDetector, heuristic::HeuristicNerDetector};

pub(crate) fn detector(log: impl Fn(&str)) -> Box<dyn NerDetector> {
    #[cfg(feature = "ner")]
    {
        detector_for_config(&super::NerConfig::default(), log)
    }
    #[cfg(not(feature = "ner"))]
    {
        log("NER: heuristic (ner-lite) enabled");
        Box::new(HeuristicNerDetector::new())
    }
}

#[cfg(feature = "ner")]
fn detector_for_config(config: &super::NerConfig, log: impl Fn(&str)) -> Box<dyn NerDetector> {
    select_detector(
        super::download::model_exists(config),
        || {
            super::ml::MlNerDetector::new(config)
                .map(|detector| Box::new(detector) as Box<dyn NerDetector>)
                .map_err(|error| error.to_string())
        },
        log,
    )
}

// Keep the selection logic testable without a downloaded model or ONNX Runtime.
#[cfg(any(feature = "ner", test))]
fn select_detector(
    model_available: bool,
    load_ml: impl FnOnce() -> Result<Box<dyn NerDetector>, String> + std::panic::UnwindSafe,
    log: impl Fn(&str),
) -> Box<dyn NerDetector> {
    if model_available {
        match std::panic::catch_unwind(load_ml) {
            Ok(Ok(detector)) => {
                log("NER: ML (DistilBERT) enabled");
                return detector;
            }
            Ok(Err(error)) => log(&format!("warning: ML NER init failed: {error}")),
            Err(_) => log("warning: ML NER init panicked; check ONNX Runtime and ORT_DYLIB_PATH"),
        }
    } else {
        log("warning: NER model not downloaded, run `anon-pii download-model`");
    }
    log("NER: heuristic (ner-lite) enabled");
    Box::new(HeuristicNerDetector::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::Anonymizer;
    use crate::ner::{MockNerDetector, NerSpan};

    fn assert_heuristic_roundtrip(detector: Box<dyn NerDetector>) {
        let text = "Please contact Dr Avery Quill.";
        let mut anonymizer = Anonymizer::new(0.5);
        anonymizer.set_ner_detector(detector);
        let (prepared, detections) = anonymizer.anonymize_text(text);
        assert!(
            detections
                .iter()
                .any(|d| { d.entity_type == "PERSON" && &text[d.start..d.end] == "Avery Quill" })
        );
        assert!(!prepared.contains("Avery Quill"));
        assert_eq!(anonymizer.mapping.restore(&prepared), text);
    }

    #[test]
    fn missing_model_uses_heuristics_without_loading_ml() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = AtomicBool::new(false);
        assert_heuristic_roundtrip(select_detector(
            false,
            || {
                called.store(true, Ordering::SeqCst);
                Err("ML loader must not run without a model".to_string())
            },
            |_| {},
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn ml_error_preserves_heuristic_roundtrip() {
        assert_heuristic_roundtrip(select_detector(
            true,
            || Err("fictional initialization error".to_string()),
            |_| {},
        ));
    }

    #[test]
    fn ml_panic_preserves_heuristic_roundtrip() {
        assert_heuristic_roundtrip(select_detector(
            true,
            || panic!("fictional runtime initialization panic"),
            |_| {},
        ));
    }

    #[test]
    fn successful_ml_is_neither_replaced_nor_supplemented() {
        let text = "Dr Avery Quill";
        for spans in [
            vec![],
            vec![NerSpan {
                text: "Avery".to_string(),
                start: 3,
                end: 8,
                score: 0.99,
                label: "PERSON".to_string(),
            }],
        ] {
            let expected_len = spans.len();
            let detector =
                select_detector(true, || Ok(Box::new(MockNerDetector { spans })), |_| {});
            let detected = detector.detect_persons(text);
            assert_eq!(detected.len(), expected_len);
            if expected_len > 0 {
                assert_eq!(&text[detected[0].start..detected[0].end], "Avery");
                assert_eq!(detected[0].score, 0.99);
            }
        }
    }

    #[cfg(feature = "ner")]
    #[test]
    fn missing_model_directory_uses_heuristics() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::ner::NerConfig {
            model_dir: directory.path().join("missing-model"),
            ..Default::default()
        };
        assert_heuristic_roundtrip(detector_for_config(&config, |_| {}));
    }
}
