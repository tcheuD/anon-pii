use std::collections::HashMap;

use crate::detection::{
    HashAlgo, MaskConfig, apply_custom_replacement, apply_encrypt, apply_hash, apply_mask,
    parse_encrypt_key,
};
use crate::mapping::Mapping;

use super::types::{AnalyzerResult, AnonymizerConfig, OperatorResult};

/// Apply per-entity anonymization operators to the text based on analyzer results.
///
/// Detections are sorted ascending and the output is built forward, using
/// `output.len()` to track correct positions in the final string. Each
/// detection's entity type is looked up in the `anonymizers` map; falls back
/// to `DEFAULT`; ultimate fallback is `replace`.
pub fn apply_operators(
    text: &str,
    mut results: Vec<AnalyzerResult>,
    anonymizers: &HashMap<String, AnonymizerConfig>,
    mapping: &mut Mapping,
) -> Result<(String, Vec<OperatorResult>), String> {
    // Sort ascending so we can build the output forward
    results.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

    // Reject overlapping ranges
    for pair in results.windows(2) {
        if pair[0].end > pair[1].start {
            return Err(format!(
                "Overlapping analyzer results: [{}, {}) and [{}, {})",
                pair[0].start, pair[0].end, pair[1].start, pair[1].end
            ));
        }
    }

    let mut output = String::new();
    let mut items: Vec<OperatorResult> = Vec::new();
    let default_config = AnonymizerConfig::default();
    let mut cursor = 0;

    for result in &results {
        // Bounds check (byte length + UTF-8 char boundary)
        if result.start > text.len()
            || result.end > text.len()
            || result.start > result.end
            || !text.is_char_boundary(result.start)
            || !text.is_char_boundary(result.end)
        {
            return Err(format!(
                "Invalid analyzer result: start={}, end={} out of range",
                result.start, result.end,
            ));
        }

        let original = &text[result.start..result.end];
        let config = anonymizers
            .get(&result.entity_type)
            .or_else(|| anonymizers.get("DEFAULT"))
            .unwrap_or(&default_config);

        let (replacement, operator_name) =
            apply_single(original, &result.entity_type, config, mapping)?;

        // Append unchanged text up to this detection, then the replacement
        output.push_str(&text[cursor..result.start]);
        let start_in_output = output.len();
        output.push_str(&replacement);

        items.push(OperatorResult {
            operator: operator_name,
            entity_type: result.entity_type.clone(),
            start: start_in_output,
            end: output.len(),
            text: replacement,
        });

        cursor = result.end;
    }

    // Append remaining text after the last detection
    output.push_str(&text[cursor..]);

    Ok((output, items))
}

fn apply_single(
    original: &str,
    entity_type: &str,
    config: &AnonymizerConfig,
    mapping: &mut Mapping,
) -> Result<(String, String), String> {
    match config {
        AnonymizerConfig::Replace { new_value } => {
            let replacement = match new_value {
                Some(val) => val.clone(),
                None => mapping.add(entity_type, original),
            };
            Ok((replacement, "replace".to_string()))
        }
        AnonymizerConfig::Redact => Ok((String::new(), "redact".to_string())),
        AnonymizerConfig::Keep => Ok((original.to_string(), "keep".to_string())),
        AnonymizerConfig::Mask {
            masking_char,
            chars_to_mask,
            from_end,
        } => {
            let mask_config = MaskConfig {
                mask_char: masking_char.unwrap_or('*'),
                fixed_count: *chars_to_mask,
                from_end: from_end.unwrap_or(false),
            };
            Ok((apply_mask(original, &mask_config), "mask".to_string()))
        }
        AnonymizerConfig::Hash { hash_type } => {
            let algo = match hash_type.as_deref() {
                Some("sha512") => HashAlgo::Sha512,
                Some("md5") => HashAlgo::Md5,
                _ => HashAlgo::Sha256,
            };
            Ok((apply_hash(original, algo), "hash".to_string()))
        }
        AnonymizerConfig::Encrypt { key } => {
            let key_bytes =
                parse_encrypt_key(key).map_err(|e| format!("Invalid encrypt key: {e}"))?;
            Ok((apply_encrypt(original, &key_bytes), "encrypt".to_string()))
        }
        AnonymizerConfig::Custom { lambda } => Ok((
            apply_custom_replacement(entity_type, lambda),
            "custom".to_string(),
        )),
    }
}
