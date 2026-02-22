/// OCR word detected in an image, with bounding box and confidence.
#[derive(Debug, Clone)]
pub struct OcrWord {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub confidence: f64,
}

/// Region of the image to redact (pixel coordinates).
#[derive(Debug, Clone)]
pub struct RedactionRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub entity_type: &'static str,
}

/// Configuration for image anonymization.
#[derive(Debug, Clone)]
pub struct ImageConfig {
    pub threshold: f64,
    pub fill_color: String,
    pub padding: u32,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            fill_color: "black".to_string(),
            padding: 2,
        }
    }
}

pub mod ocr;

#[cfg(test)]
mod tests;
