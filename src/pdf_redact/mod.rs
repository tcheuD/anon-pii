// Crate choice: `lopdf` (0.40.0) — chosen over `pdf-extract` and `pdf` (pdf-rs)
// because it provides direct access to PDF content streams (Tm/Td/Tj/TJ text
// operators), which is essential for extracting text with bounding-box positions.
// `pdf-extract` only yields plain text without coordinates; `pdf` (pdf-rs) is
// less mature and has fewer downstream users. `lopdf` also supports PDF
// modification, needed here for writing visual masking rectangles.

use std::fmt;

/// Coordinates are in PDF user-space points (1/72 inch), origin at bottom-left.
#[derive(Debug, Clone)]
pub struct PdfWord {
    pub text: String,
    pub page: u32,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone)]
pub struct RedactionRegion {
    pub page: u32,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub entity_type: String,
}

#[derive(Debug, Clone)]
pub struct PdfConfig {
    pub threshold: f64,
    pub fill_color: String,
    pub padding: f64,
}

impl Default for PdfConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            fill_color: "black".to_string(),
            padding: 2.0,
        }
    }
}

#[derive(Debug)]
pub enum PdfError {
    Parse(String),
    Io(String),
    Extraction(String),
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdfError::Parse(msg) => write!(f, "PDF parse failed: {msg}"),
            PdfError::Io(msg) => write!(f, "PDF I/O failed: {msg}"),
            PdfError::Extraction(msg) => write!(f, "PDF text extraction failed: {msg}"),
        }
    }
}

impl std::error::Error for PdfError {}

pub mod extract;
pub mod redact;
pub mod region;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_word_construction() {
        let word = PdfWord {
            text: "John".to_string(),
            page: 1,
            x: 72.0,
            y: 700.0,
            width: 40.5,
            height: 12.0,
        };
        assert_eq!(word.text, "John");
        assert_eq!(word.page, 1);
        assert!((word.x - 72.0).abs() < f64::EPSILON);
        assert!((word.y - 700.0).abs() < f64::EPSILON);
        assert!((word.width - 40.5).abs() < f64::EPSILON);
        assert!((word.height - 12.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pdf_word_clone() {
        let word = PdfWord {
            text: "test".to_string(),
            page: 0,
            x: 0.0,
            y: 0.0,
            width: 10.0,
            height: 10.0,
        };
        let cloned = word.clone();
        assert_eq!(cloned.text, "test");
        assert_eq!(cloned.page, 0);
    }

    #[test]
    fn test_redaction_region_construction() {
        let region = RedactionRegion {
            page: 2,
            x: 50.0,
            y: 600.0,
            width: 120.0,
            height: 14.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        };
        assert_eq!(region.page, 2);
        assert!((region.x - 50.0).abs() < f64::EPSILON);
        assert_eq!(region.entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn test_pdf_config_default() {
        let config = PdfConfig::default();
        assert!((config.threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.fill_color, "black");
        assert!((config.padding - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pdf_error_parse_display() {
        let err = PdfError::Parse("invalid xref table".to_string());
        assert!(err.to_string().contains("invalid xref table"));
    }

    #[test]
    fn test_pdf_error_io_display() {
        let err = PdfError::Io("file not found".to_string());
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_pdf_error_extraction_display() {
        let err = PdfError::Extraction("no text on page".to_string());
        assert!(err.to_string().contains("no text on page"));
    }

    #[test]
    fn test_pdf_error_is_std_error() {
        let err = PdfError::Parse("test".to_string());
        let _: &dyn std::error::Error = &err;
    }
}
