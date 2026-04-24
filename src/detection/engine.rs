use std::borrow::Cow;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use super::names::{build_byte_offset_map, extend_person_span, is_name_like_word};
use super::normalize::{
    collapse_newlines, decode_percent_encoding, decode_unicode_escapes, strip_diacritics,
    MULTILINE_ENTITY_TYPES,
};
use super::operators::{apply_custom_replacement, apply_encrypt, apply_hash, apply_mask};
use super::types::{Detection, Operator};
use super::Anonymizer;
use crate::ner::PERSON_BLOCKLIST;
use crate::patterns::{
    iban_mod97, luhn_check, valid_aba_routing, valid_au_abn, valid_au_acn, valid_au_medicare,
    valid_au_tfn, valid_card_prefix, valid_es_nie, valid_es_nif, valid_fi_identity_code,
    valid_in_aadhaar, valid_in_gstin, valid_it_fiscal_code, valid_kr_brn, valid_kr_frn,
    valid_kr_rrn, valid_mac, valid_pl_pesel, valid_sg_nric_fin, valid_si_emso, valid_si_tax_number,
    valid_th_tnin, valid_uk_nhs, valid_uk_nino, valid_us_itin, valid_us_ssn, CREW_CODE_BLOCKLIST,
};

impl Anonymizer {
    pub fn anonymize_text(&mut self, text: &str) -> (String, Vec<Detection>) {
        // NFKC normalization converts fullwidth digits, confusable homoglyphs,
        // and other Unicode variants to their canonical ASCII equivalents so
        // that regex patterns match consistently.
        let normalized: String = text.nfkc().collect();
        // Decode JSON-style \uXXXX escape sequences (e.g. \u0040 -> @) so that
        // PII hidden behind unicode escapes in log lines is detected.
        let normalized = decode_unicode_escapes(&normalized);
        // Decode URL percent-encoding (e.g. %40 -> @) so that PII in HTTP
        // access log query strings is detected.
        let normalized = decode_percent_encoding(&normalized);
        let text = normalized.as_str();

        let mut detections: Vec<Detection> = Vec::new();

        for pat in &self.patterns {
            // Early threshold check: consider maximum possible score (with boost)
            let max_score = if !pat.context_keywords.is_empty() && !pat.context_required {
                (pat.score + self.context_boost).min(1.0)
            } else {
                pat.score
            };
            if max_score < self.threshold {
                continue;
            }

            for mat in pat.regex.find_iter(text) {
                // Check context presence
                let has_ctx = if !pat.context_keywords.is_empty() {
                    self.has_context(text, mat.start(), mat.end(), &pat.context_keywords)
                } else {
                    false
                };

                // Context gating: required mode skips when no context found
                if pat.context_required && !pat.context_keywords.is_empty() && !has_ctx {
                    continue;
                }

                // FR_SSN: reject matches embedded in longer digit sequences
                if pat.entity_type == "FR_SSN" {
                    let bytes = text.as_bytes();
                    if (mat.start() > 0 && bytes[mat.start() - 1].is_ascii_digit())
                        || (mat.end() < bytes.len() && bytes[mat.end()].is_ascii_digit())
                    {
                        continue;
                    }
                }

                // Crew code blocklist
                if pat.entity_type == "CREW_CODE" {
                    let matched = mat.as_str();
                    if CREW_CODE_BLOCKLIST.contains(&matched) {
                        continue;
                    }
                }

                // Credit card validation: Luhn checksum + known issuer prefix
                if pat.entity_type == "CREDIT_CARD" {
                    let matched = mat.as_str();
                    if !luhn_check(matched) || !valid_card_prefix(matched) {
                        continue;
                    }
                }
                if pat.entity_type == "IBAN_CODE" && !iban_mod97(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "MAC_ADDRESS" && !valid_mac(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "US_SSN" && !valid_us_ssn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "US_ITIN" && !valid_us_itin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ABA_ROUTING" && !valid_aba_routing(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "UK_NHS" && !valid_uk_nhs(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "UK_NINO" && !valid_uk_nino(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ES_NIF" && !valid_es_nif(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ES_NIE" && !valid_es_nie(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IT_FISCAL_CODE" && !valid_it_fiscal_code(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IN_AADHAAR" && !valid_in_aadhaar(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IN_GSTIN" && !valid_in_gstin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_ABN" && !valid_au_abn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_ACN" && !valid_au_acn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_TFN" && !valid_au_tfn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_MEDICARE" && !valid_au_medicare(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_RRN" && !valid_kr_rrn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_FRN" && !valid_kr_frn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_BRN" && !valid_kr_brn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "SG_NRIC_FIN" && !valid_sg_nric_fin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "PL_PESEL" && !valid_pl_pesel(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "SI_EMSO" && !valid_si_emso(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "SI_TAX_NUMBER" && !valid_si_tax_number(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                    && !valid_fi_identity_code(mat.as_str())
                {
                    continue;
                }
                if pat.entity_type == "TH_TNIN" && !valid_th_tnin(mat.as_str()) {
                    continue;
                }

                // Compute detection score with optional context boost
                let boosted = !pat.context_required && !pat.context_keywords.is_empty() && has_ctx;
                let detection_score = if boosted {
                    (pat.score + self.context_boost).min(1.0)
                } else {
                    pat.score
                };

                // Per-detection threshold check (for boost patterns without context)
                if detection_score < self.threshold {
                    continue;
                }

                // Min-score-with-context filter: reject boosted matches below floor
                if boosted
                    && self.min_score_with_context > 0.0
                    && detection_score < self.min_score_with_context
                {
                    continue;
                }

                detections.push(Detection {
                    entity_type: pat.entity_type.clone(),
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    score: detection_score,
                });
            }
        }

        // Multiline second pass: collapse whitespace+newline runs into a single
        // space and re-run patterns that can span line breaks (credit cards, IBANs).
        // Detections are mapped back to original byte positions.
        if let Some((collapsed, pos_map)) = collapse_newlines(text) {
            for pat in &self.patterns {
                if !MULTILINE_ENTITY_TYPES.contains(&pat.entity_type.as_ref()) {
                    continue;
                }
                let max_score = if !pat.context_keywords.is_empty() && !pat.context_required {
                    (pat.score + self.context_boost).min(1.0)
                } else {
                    pat.score
                };
                if max_score < self.threshold {
                    continue;
                }
                for mat in pat.regex.find_iter(&collapsed) {
                    // Only consider matches that actually span a newline
                    let orig_start = pos_map[mat.start()];
                    let orig_end_idx = (mat.end() - 1).min(pos_map.len() - 1);
                    let orig_end_byte = pos_map[orig_end_idx];
                    let orig_span = &text[orig_start..=orig_end_byte];
                    if !orig_span.contains('\n') {
                        continue; // Already found by the single-line pass
                    }

                    // Compute original end as one past the last byte
                    let orig_end = if mat.end() < pos_map.len() {
                        pos_map[mat.end()]
                    } else {
                        text.len()
                    };

                    let matched = mat.as_str();

                    if pat.entity_type == "CREDIT_CARD"
                        && (!luhn_check(matched) || !valid_card_prefix(matched))
                    {
                        continue;
                    }
                    if pat.entity_type == "IBAN_CODE" && !iban_mod97(matched) {
                        continue;
                    }
                    if pat.entity_type == "MAC_ADDRESS" && !valid_mac(matched) {
                        continue;
                    }
                    if pat.entity_type == "US_SSN" && !valid_us_ssn(matched) {
                        continue;
                    }
                    if pat.entity_type == "US_ITIN" && !valid_us_itin(matched) {
                        continue;
                    }
                    if pat.entity_type == "ABA_ROUTING" && !valid_aba_routing(matched) {
                        continue;
                    }
                    if pat.entity_type == "UK_NHS" && !valid_uk_nhs(matched) {
                        continue;
                    }
                    if pat.entity_type == "UK_NINO" && !valid_uk_nino(matched) {
                        continue;
                    }
                    if pat.entity_type == "ES_NIF" && !valid_es_nif(matched) {
                        continue;
                    }
                    if pat.entity_type == "ES_NIE" && !valid_es_nie(matched) {
                        continue;
                    }
                    if pat.entity_type == "IT_FISCAL_CODE" && !valid_it_fiscal_code(matched) {
                        continue;
                    }
                    if pat.entity_type == "IN_AADHAAR" && !valid_in_aadhaar(matched) {
                        continue;
                    }
                    if pat.entity_type == "IN_GSTIN" && !valid_in_gstin(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_ABN" && !valid_au_abn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_ACN" && !valid_au_acn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_TFN" && !valid_au_tfn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_MEDICARE" && !valid_au_medicare(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_RRN" && !valid_kr_rrn(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_FRN" && !valid_kr_frn(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_BRN" && !valid_kr_brn(matched) {
                        continue;
                    }
                    if pat.entity_type == "SG_NRIC_FIN" && !valid_sg_nric_fin(matched) {
                        continue;
                    }
                    if pat.entity_type == "PL_PESEL" && !valid_pl_pesel(matched) {
                        continue;
                    }
                    if pat.entity_type == "SI_EMSO" && !valid_si_emso(matched) {
                        continue;
                    }
                    if pat.entity_type == "SI_TAX_NUMBER" && !valid_si_tax_number(matched) {
                        continue;
                    }
                    if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                        && !valid_fi_identity_code(matched)
                    {
                        continue;
                    }
                    if pat.entity_type == "TH_TNIN" && !valid_th_tnin(matched) {
                        continue;
                    }

                    let has_ctx = if !pat.context_keywords.is_empty() {
                        self.has_context(text, orig_start, orig_end, &pat.context_keywords)
                    } else {
                        false
                    };
                    if pat.context_required && !pat.context_keywords.is_empty() && !has_ctx {
                        continue;
                    }
                    let boosted =
                        !pat.context_required && !pat.context_keywords.is_empty() && has_ctx;
                    let detection_score = if boosted {
                        (pat.score + self.context_boost).min(1.0)
                    } else {
                        pat.score
                    };
                    if detection_score < self.threshold {
                        continue;
                    }
                    if boosted
                        && self.min_score_with_context > 0.0
                        && detection_score < self.min_score_with_context
                    {
                        continue;
                    }

                    detections.push(Detection {
                        entity_type: pat.entity_type.clone(),
                        original: matched.to_string(),
                        start: orig_start,
                        end: orig_end,
                        score: detection_score,
                    });
                }
            }
        }

        // Inject NER-based PERSON and LOCATION detections
        if let Some(ref ner) = self.ner_detector {
            for span in ner.detect_persons(text) {
                if span.score >= self.threshold {
                    let trimmed = span.text.trim();
                    let is_person = span.label == "PERSON" || span.label == "PER";
                    let is_location = span.label == "LOCATION" || span.label == "LOC";

                    if is_person {
                        if PERSON_BLOCKLIST.contains(&trimmed) {
                            continue;
                        }
                        let (ext_text, ext_end) = extend_person_span(text, &span.text, span.end);
                        detections.push(Detection {
                            entity_type: Cow::Borrowed("PERSON"),
                            original: ext_text,
                            start: span.start,
                            end: ext_end,
                            score: span.score,
                        });
                    } else if is_location {
                        detections.push(Detection {
                            entity_type: Cow::Borrowed("LOCATION"),
                            original: span.text.clone(),
                            start: span.start,
                            end: span.end,
                            score: span.score,
                        });
                    }
                }
            }
        }

        // Sign-off name detection: find names after common closing salutations.
        // Catches nicknames and informal names like "Best regards,\nPrzemek".
        {
            static SIGNOFF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?im)(?:best\s+regards|regards|brgds|brds|cordialement|cdlt|bien\s+[àa]\s+vous|sincerely|cheers|merci|thanks)[,.]?\s*\n?\s*([A-Z\p{Lu}][\p{L}'-]+)"
                ).unwrap()
            });
            for cap in SIGNOFF_RE.captures_iter(text) {
                if let Some(name_match) = cap.get(1) {
                    let name = name_match.as_str();
                    if name.len() >= 2
                        && is_name_like_word(name)
                        && !PERSON_BLOCKLIST
                            .iter()
                            .any(|&b| b.eq_ignore_ascii_case(name))
                    {
                        let already_covered = detections
                            .iter()
                            .any(|d| d.start <= name_match.start() && d.end >= name_match.end());
                        if !already_covered {
                            detections.push(Detection {
                                entity_type: Cow::Borrowed("PERSON"),
                                original: name.to_string(),
                                start: name_match.start(),
                                end: name_match.end(),
                                score: 0.60,
                            });
                        }
                    }
                }
            }
        }

        // Name consistency pass: if "Gael FONTAINE" was detected as PERSON,
        // also detect bare "Gael" and "FONTAINE" elsewhere in the text.
        // Uses accent-insensitive matching so "Gael" is caught when "Gael" was detected.
        {
            let mut name_parts: Vec<String> = Vec::new();
            for d in detections
                .iter()
                .filter(|d| d.entity_type == "PERSON" && d.original.contains(' '))
            {
                let words: Vec<&str> = d.original.split_whitespace().collect();
                // First name
                if let Some(first) = words.first() {
                    if first.len() >= 2 {
                        name_parts.push(first.to_string());
                    }
                }
                // Last name(s) — at least 3 chars to avoid false positives
                for word in words.iter().skip(1) {
                    if word.len() >= 3 {
                        name_parts.push(word.to_string());
                    }
                }
            }
            name_parts.sort();
            name_parts.dedup();

            // Pre-compute stripped text and offset map once for accent-insensitive matching
            let stripped_text = strip_diacritics(text);
            let offset_map = build_byte_offset_map(text);

            for name_part in &name_parts {
                Self::find_bare_name_occurrences(
                    text,
                    name_part,
                    &stripped_text,
                    &offset_map,
                    &mut detections,
                );
            }
        }

        // Drop PASSWORD detections that fully contain a more specific detection
        // (e.g., PASSWORD wrapping a SECRET_KEY or AUTH_TOKEN value).
        if detections.iter().any(|d| d.entity_type == "PASSWORD") {
            let specific_spans: Vec<(usize, usize)> = detections
                .iter()
                .filter(|d| d.entity_type != "PASSWORD")
                .map(|d| (d.start, d.end))
                .collect();
            if !specific_spans.is_empty() {
                detections.retain(|det| {
                    if det.entity_type != "PASSWORD" {
                        return true;
                    }
                    !specific_spans
                        .iter()
                        .any(|&(s, e)| s >= det.start && e <= det.end)
                });
            }
        }

        // Sort by position asc, then span length desc, then score desc
        // Matches Python/Presidio overlap resolution: position-first
        detections.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        // Remove overlapping detections (keep first = longest/highest score)
        let mut filtered: Vec<Detection> = Vec::new();
        for det in detections {
            let overlaps = filtered
                .iter()
                .any(|f| det.start < f.end && det.end > f.start);
            if !overlaps {
                filtered.push(det);
            }
        }

        // Sort by position for display
        filtered.sort_by_key(|d| d.start);

        // Extract inner PII from URL query parameters for audit visibility.
        // These are reported in the detection list but not used for replacement
        // (the entire URL is already masked as [URL_...]).
        let mut url_inner_detections: Vec<Detection> = Vec::new();
        for det in &filtered {
            if det.entity_type == "URL" {
                if let Some(qpos) = det.original.find('?') {
                    let query = &det.original[qpos + 1..];
                    for param in query.split('&') {
                        if let Some(eq) = param.find('=') {
                            let value = &param[eq + 1..];
                            if value.is_empty() {
                                continue;
                            }
                            let decoded = decode_percent_encoding(value);
                            for pat in &self.patterns {
                                if pat.entity_type == "URL" {
                                    continue;
                                }
                                for mat in pat.regex.find_iter(&decoded) {
                                    if pat.entity_type == "CREDIT_CARD"
                                        && (!luhn_check(mat.as_str())
                                            || !valid_card_prefix(mat.as_str()))
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IBAN_CODE" && !iban_mod97(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "CREW_CODE"
                                        && CREW_CODE_BLOCKLIST.contains(&mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "US_ITIN" && !valid_us_itin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "ABA_ROUTING"
                                        && !valid_aba_routing(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "UK_NHS" && !valid_uk_nhs(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "UK_NINO" && !valid_uk_nino(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "ES_NIF" && !valid_es_nif(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "ES_NIE" && !valid_es_nie(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "IT_FISCAL_CODE"
                                        && !valid_it_fiscal_code(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IN_AADHAAR"
                                        && !valid_in_aadhaar(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IN_GSTIN"
                                        && !valid_in_gstin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_ABN" && !valid_au_abn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_ACN" && !valid_au_acn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_TFN" && !valid_au_tfn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_MEDICARE"
                                        && !valid_au_medicare(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_RRN" && !valid_kr_rrn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_FRN" && !valid_kr_frn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_BRN" && !valid_kr_brn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "SG_NRIC_FIN"
                                        && !valid_sg_nric_fin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "PL_PESEL"
                                        && !valid_pl_pesel(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "SI_EMSO" && !valid_si_emso(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "SI_TAX_NUMBER"
                                        && !valid_si_tax_number(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                                        && !valid_fi_identity_code(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "TH_TNIN" && !valid_th_tnin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    let score = pat.score;
                                    if score < self.threshold {
                                        continue;
                                    }
                                    url_inner_detections.push(Detection {
                                        entity_type: pat.entity_type.clone(),
                                        original: mat.as_str().to_string(),
                                        start: det.start,
                                        end: det.start,
                                        score,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Replace from end to start
        let mut result = text.to_string();
        for det in filtered.iter().rev() {
            let replacement = match self.operator {
                Operator::Token => self.mapping.add(&det.entity_type, &det.original),
                Operator::Redact => String::new(),
                Operator::Keep => continue,
                Operator::Mask => apply_mask(&det.original, &self.mask_config),
                Operator::Hash => apply_hash(&det.original, self.hash_algo),
                Operator::Encrypt => apply_encrypt(
                    &det.original,
                    self.encrypt_key.as_ref().expect("encrypt_key required"),
                ),
                Operator::Custom => apply_custom_replacement(
                    &det.entity_type,
                    self.replace_with.as_deref().expect("replace_with required"),
                ),
            };
            result = format!(
                "{}{}{}",
                &result[..det.start],
                replacement,
                &result[det.end..]
            );
        }

        filtered.extend(url_inner_detections);
        (result, filtered)
    }
}
