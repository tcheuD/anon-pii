use std::borrow::Cow;

use super::Anonymizer;
use super::normalize::strip_diacritics;
use super::types::Detection;
use crate::ner::PERSON_BLOCKLIST;
use crate::patterns::CREW_CODE_BLOCKLIST;

/// Build a sorted mapping from stripped byte offset -> original byte offset.
/// Each entry is (stripped_byte, orig_byte) at char boundaries.
pub(super) fn build_byte_offset_map(original: &str) -> Vec<(usize, usize)> {
    let mut map = Vec::with_capacity(original.len());
    let mut stripped_offset = 0;
    for (orig_offset, ch) in original.char_indices() {
        map.push((stripped_offset, orig_offset));
        let mut ch_stripped_len = 0;
        unicode_normalization::char::decompose_canonical(ch, |nfd_ch| {
            if !unicode_normalization::char::is_combining_mark(nfd_ch) {
                ch_stripped_len += nfd_ch.len_utf8();
            }
        });
        stripped_offset += ch_stripped_len;
    }
    map.push((stripped_offset, original.len()));
    map
}

/// Map a stripped byte offset back to the original byte offset using binary search.
pub(super) fn stripped_to_original_offset(
    map: &[(usize, usize)],
    stripped_offset: usize,
) -> Option<usize> {
    match map.binary_search_by_key(&stripped_offset, |&(s, _)| s) {
        Ok(i) => Some(map[i].1),
        Err(i) if i > 0 && i < map.len() => Some(map[i].1),
        _ => None,
    }
}

/// Check if a word looks like a name component: ALL-CAPS ("DUPONT") or Title-case ("Kowalski").
pub(super) fn is_name_like_word(word: &str) -> bool {
    if word.len() < 2 {
        return false;
    }
    let mut chars = word.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_uppercase() {
        return false;
    }
    // ALL-CAPS: every char is uppercase, hyphen, or apostrophe
    let all_upper = word
        .chars()
        .all(|c| c.is_uppercase() || c == '-' || c == '\'');
    if all_upper {
        return true;
    }
    // Title-case: first char uppercase, rest are lowercase/hyphen/apostrophe
    // (with uppercase allowed after hyphen for compound names like "Le-Goff")
    chars.all(|c| c.is_lowercase() || c == '-' || c == '\'')
}

/// Extend a PERSON span to include following name-like words (ALL-CAPS or Title-case).
/// e.g. if NER detected "Damien" at end=6, and text continues with " DUPONT" or " Kowalski",
/// extend to "Damien DUPONT" or "Damien Kowalski".
pub(super) fn extend_person_span(text: &str, span_text: &str, span_end: usize) -> (String, usize) {
    let mut end = span_end;
    let mut result = span_text.to_string();
    // Only look at remaining text on the same line (don't cross newlines)
    let remaining = &text[end..];
    let same_line = remaining.split('\n').next().unwrap_or("");

    for word in same_line.split_whitespace().take(2) {
        let trimmed = word.trim_end_matches(|c: char| c.is_ascii_punctuation());
        if is_name_like_word(trimmed)
            && !PERSON_BLOCKLIST
                .iter()
                .any(|&b| b.eq_ignore_ascii_case(trimmed))
            && !CREW_CODE_BLOCKLIST.contains(&trimmed)
        {
            // Find the actual position of this word in the remaining text
            if let Some(word_offset) = text[end..].find(trimmed) {
                let new_end = end + word_offset + trimmed.len();
                // Append the exact original bytes we just consumed. Re-slicing
                // from `span_end - span_text.len()` would assume the detected
                // span_text has the same byte length as its source span, which
                // is false when NER returns normalized text.
                result.push_str(&text[end..new_end]);
                end = new_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    (result, end)
}

impl Anonymizer {
    /// Search for bare occurrences of a name part in text. Exact match first,
    /// then accent-insensitive via pre-computed stripped text + offset map.
    pub(super) fn find_bare_name_occurrences(
        text: &str,
        name: &str,
        stripped_text: &str,
        offset_map: &[(usize, usize)],
        detections: &mut Vec<Detection>,
    ) {
        // Exact match pass
        Self::find_name_at_word_boundaries(text, name, detections);

        // Accent-insensitive pass (only if stripping changes the name)
        let stripped_name = strip_diacritics(name);
        if stripped_name != name {
            Self::find_name_in_stripped_text(
                text,
                stripped_text,
                &stripped_name,
                offset_map,
                detections,
            );
        }
    }

    fn find_name_at_word_boundaries(text: &str, search: &str, detections: &mut Vec<Detection>) {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(search) {
            let abs_pos = search_from + pos;
            let abs_end = abs_pos + search.len();

            let at_word_start =
                abs_pos == 0 || !text[..abs_pos].chars().last().unwrap().is_alphanumeric();
            let at_word_end =
                abs_end >= text.len() || !text[abs_end..].chars().next().unwrap().is_alphanumeric();

            if at_word_start && at_word_end {
                let already_covered = detections
                    .iter()
                    .any(|d| d.start <= abs_pos && d.end >= abs_end);
                if !already_covered {
                    detections.push(Detection {
                        entity_type: Cow::Borrowed("PERSON"),
                        original: search.to_string(),
                        start: abs_pos,
                        end: abs_end,
                        score: 0.50,
                    });
                }
            }

            search_from = abs_pos + search.len();
        }
    }

    /// Find accent-stripped name in text using pre-computed stripped text and offset map.
    fn find_name_in_stripped_text(
        original_text: &str,
        stripped_text: &str,
        stripped_name: &str,
        offset_map: &[(usize, usize)],
        detections: &mut Vec<Detection>,
    ) {
        let mut search_from = 0;
        while let Some(pos) = stripped_text[search_from..].find(stripped_name) {
            let stripped_start = search_from + pos;
            let stripped_end = stripped_start + stripped_name.len();

            let orig_start = stripped_to_original_offset(offset_map, stripped_start);
            let orig_end = stripped_to_original_offset(offset_map, stripped_end);

            if let (Some(abs_pos), Some(abs_end)) = (orig_start, orig_end) {
                let at_word_start = abs_pos == 0
                    || !original_text[..abs_pos]
                        .chars()
                        .last()
                        .unwrap()
                        .is_alphanumeric();
                let at_word_end = abs_end >= original_text.len()
                    || !original_text[abs_end..]
                        .chars()
                        .next()
                        .unwrap()
                        .is_alphanumeric();

                if at_word_start && at_word_end {
                    let already_covered = detections
                        .iter()
                        .any(|d| d.start <= abs_pos && d.end >= abs_end);
                    if !already_covered {
                        let matched_text = &original_text[abs_pos..abs_end];
                        detections.push(Detection {
                            entity_type: Cow::Borrowed("PERSON"),
                            original: matched_text.to_string(),
                            start: abs_pos,
                            end: abs_end,
                            score: 0.50,
                        });
                    }
                }
            }

            search_from = stripped_end;
        }
    }
}
