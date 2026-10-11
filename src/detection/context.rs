use super::{Anonymizer, CompiledPattern};
use crate::patterns::{CONTEXT_WINDOW, UK_IBAN_PRINT_PATTERN};

impl Anonymizer {
    pub(super) fn has_context(
        &self,
        text: &str,
        start: usize,
        end: usize,
        pattern: &CompiledPattern,
    ) -> bool {
        let keywords = &pattern.context_keywords;
        if keywords.is_empty() {
            return false;
        }
        // 1. Local window check (fast path). CONTEXT_WINDOW is a count of
        //    CHARACTERS, not bytes: on multibyte text (e.g. CJK, 3 bytes/char)
        //    a byte window would cover far fewer characters than intended and
        //    miss context keywords. char_indices boundaries are always valid.
        let window_start = text[..start]
            .char_indices()
            .nth_back(CONTEXT_WINDOW - 1)
            .map(|(i, _)| i)
            .unwrap_or(0);
        let window_end = text[end..]
            .char_indices()
            .nth(CONTEXT_WINDOW)
            .map(|(i, _)| end + i)
            .unwrap_or(text.len());
        // A GB print value's bank letters can themselves spell "bank" or
        // contain "bic". This rule requires context outside the full match.
        // Check its identity as well as its name so unrelated custom rules
        // retain their established context behavior.
        let external_only = pattern.name == "uk_iban_print"
            && pattern.entity_type == "IBAN_CODE"
            && pattern.regex.as_str() == UK_IBAN_PRINT_PATTERN
            && pattern.context_required;
        let has_local_context = if external_only {
            let before = text[window_start..start].to_lowercase();
            let after = text[end..window_end].to_lowercase();
            keywords
                .iter()
                .any(|kw| before.contains(*kw) || after.contains(*kw))
        } else {
            let lower = text[window_start..window_end].to_lowercase();
            keywords.iter().any(|kw| lower.contains(*kw))
        };
        if has_local_context {
            return true;
        }
        // 2. Column-header check: find the column offset of the match on its
        //    line, then scan upward for a header line that has a keyword at a
        //    similar column position.
        self.has_column_header_context(text, start, keywords)
    }

    /// Look above the match for a header line where a keyword sits at the same
    /// column position (+/-4 chars) as the match.
    fn has_column_header_context(&self, text: &str, start: usize, keywords: &[&str]) -> bool {
        // Find the line containing the match and its column offset.
        let line_start = text[..start].rfind('\n').map_or(0, |p| p + 1);
        let col = start - line_start;

        // Scan up to 20 lines above for a header line.
        let prefix = &text[..line_start];
        let lines_above: Vec<&str> = prefix.lines().rev().take(20).collect();

        for header_line in &lines_above {
            let header_lower = header_line.to_lowercase();
            for kw in keywords {
                if let Some(kw_pos) = header_lower.find(kw) {
                    // Check if the keyword column overlaps with the match column (+/-4 chars tolerance)
                    let kw_end = kw_pos + kw.len();
                    if col + 4 >= kw_pos && col <= kw_end + 4 {
                        return true;
                    }
                }
            }
        }
        false
    }
}
