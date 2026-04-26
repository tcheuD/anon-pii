use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::detection::Anonymizer;
use crate::mapping::Mapping;
use crate::patterns::{MAX_INPUT_SIZE, PATTERNS};

use super::operators::apply_operators;
use super::types::{AnalyzeRequest, AnonymizeRequest, AnonymizeResponse, RecognizerResult};

pub async fn analyze(Json(req): Json<AnalyzeRequest>) -> Response {
    if req.text.len() as u64 > MAX_INPUT_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Input too large").into_response();
    }

    let mut anonymizer = Anonymizer::new(req.score_threshold.clamp(0.0, 1.0));

    // Enable NER based on compiled features
    #[cfg(feature = "ner")]
    {
        use crate::ner::{NerConfig, download::model_exists, ml::MlNerDetector};
        let config = NerConfig::default();
        if model_exists(&config) {
            if let Ok(Ok(det)) = std::panic::catch_unwind(|| MlNerDetector::new(&config)) {
                anonymizer.set_ner_detector(Box::new(det));
            }
        }
    }
    #[cfg(all(feature = "ner-lite", not(feature = "ner")))]
    {
        use crate::ner::heuristic::HeuristicNerDetector;
        anonymizer.set_ner_detector(Box::new(HeuristicNerDetector::new()));
    }

    let detections = anonymizer.analyze(&req.text);

    let mut results: Vec<RecognizerResult> = detections
        .into_iter()
        .map(|d| RecognizerResult {
            entity_type: d.entity_type.to_string(),
            start: d.start,
            end: d.end,
            score: d.score,
        })
        .collect();

    // Filter by requested entity types if specified
    if let Some(ref entities) = req.entities {
        let allowed: BTreeSet<&str> = entities.iter().map(|s| s.as_str()).collect();
        results.retain(|r| allowed.contains(r.entity_type.as_str()));
    }

    Json(results).into_response()
}

pub async fn anonymize(Json(req): Json<AnonymizeRequest>) -> Response {
    if req.text.len() as u64 > MAX_INPUT_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Input too large").into_response();
    }

    let mut mapping = Mapping::new();

    match apply_operators(
        &req.text,
        req.analyzer_results,
        &req.anonymizers,
        &mut mapping,
    ) {
        Ok((text, items)) => Json(AnonymizeResponse { text, items }).into_response(),
        Err(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SupportedEntitiesQuery {
    #[allow(dead_code)]
    pub language: Option<String>,
}

pub async fn supported_entities(Query(_q): Query<SupportedEntitiesQuery>) -> Response {
    let mut types: BTreeSet<&str> = BTreeSet::new();
    for p in PATTERNS {
        types.insert(p.entity_type);
    }

    // Add NER entity types when features are compiled in
    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    {
        types.insert("PERSON");
    }
    #[cfg(feature = "ner")]
    {
        types.insert("LOCATION");
    }

    let sorted: Vec<&str> = types.into_iter().collect();
    Json(sorted).into_response()
}

pub async fn health() -> impl IntoResponse {
    StatusCode::OK
}
