use std::fmt;
use std::path::{Path, PathBuf};

use image_crate::GenericImageView;

use super::RedactionRegion;

/// Errors that can occur during image redaction.
#[derive(Debug)]
pub enum RedactError {
    InvalidColor(String),
    ImageLoad { path: PathBuf, source: String },
    ImageSave { path: PathBuf, source: String },
    UnsupportedFormat { extension: String },
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedactError::InvalidColor(c) => write!(f, "invalid fill color: {c}"),
            RedactError::ImageLoad { path, source } => {
                write!(f, "failed to load image {}: {source}", path.display())
            }
            RedactError::ImageSave { path, source } => {
                write!(f, "failed to save image {}: {source}", path.display())
            }
            RedactError::UnsupportedFormat { extension } => {
                write!(f, "unsupported output format: {extension}")
            }
        }
    }
}

impl std::error::Error for RedactError {}

/// Parse a color string into an RGBA pixel value.
///
/// Accepts named colors (black, white, red, green, blue, yellow, magenta, cyan,
/// gray/grey) or hex strings prefixed with `#` (3-digit or 6-digit).
pub fn parse_fill_color(color: &str) -> Result<[u8; 4], RedactError> {
    let lower = color.to_lowercase();
    match lower.as_str() {
        "black" => return Ok([0, 0, 0, 255]),
        "white" => return Ok([255, 255, 255, 255]),
        "red" => return Ok([255, 0, 0, 255]),
        "green" => return Ok([0, 128, 0, 255]),
        "blue" => return Ok([0, 0, 255, 255]),
        "yellow" => return Ok([255, 255, 0, 255]),
        "magenta" => return Ok([255, 0, 255, 255]),
        "cyan" => return Ok([0, 255, 255, 255]),
        "gray" | "grey" => return Ok([128, 128, 128, 255]),
        _ => {}
    }

    let hex = lower
        .strip_prefix('#')
        .ok_or_else(|| RedactError::InvalidColor(color.to_string()))?;

    let parse_hex_byte = |s: &str| -> Result<u8, RedactError> {
        u8::from_str_radix(s, 16).map_err(|_| RedactError::InvalidColor(color.to_string()))
    };

    match hex.len() {
        6 => {
            let r = parse_hex_byte(&hex[0..2])?;
            let g = parse_hex_byte(&hex[2..4])?;
            let b = parse_hex_byte(&hex[4..6])?;
            Ok([r, g, b, 255])
        }
        3 => {
            let r = parse_hex_byte(&hex[0..1].repeat(2))?;
            let g = parse_hex_byte(&hex[1..2].repeat(2))?;
            let b = parse_hex_byte(&hex[2..3].repeat(2))?;
            Ok([r, g, b, 255])
        }
        _ => Err(RedactError::InvalidColor(color.to_string())),
    }
}

/// Fill a rectangular region on the image with the given color.
fn draw_filled_rect(img: &mut image_crate::DynamicImage, region: &RedactionRegion, color: [u8; 4]) {
    let (img_w, img_h) = img.dimensions();

    let x1 = region.x.min(img_w);
    let y1 = region.y.min(img_h);
    let x2 = (region.x.saturating_add(region.width)).min(img_w);
    let y2 = (region.y.saturating_add(region.height)).min(img_h);

    if x1 >= x2 || y1 >= y2 {
        return;
    }

    let pixel = image_crate::Rgba(color);

    // Try zero-copy path first
    if let Some(buf) = img.as_mut_rgba8() {
        for py in y1..y2 {
            for px in x1..x2 {
                buf.put_pixel(px, py, pixel);
            }
        }
    } else {
        let mut buf = img.to_rgba8();
        for py in y1..y2 {
            for px in x1..x2 {
                buf.put_pixel(px, py, pixel);
            }
        }
        *img = image_crate::DynamicImage::ImageRgba8(buf);
    }
}

/// Redact regions of an image by filling them with a solid color.
///
/// Opens the input image, draws filled rectangles over each region, and saves
/// to the output path. Only PNG and JPEG output formats are supported. EXIF
/// metadata is naturally stripped since the `image` crate does not re-embed it.
pub fn redact_image(
    input: &Path,
    output: &Path,
    regions: &[RedactionRegion],
    fill_color: &str,
) -> Result<(), RedactError> {
    let ext = output
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "png" | "jpg" | "jpeg" => {}
        _ => {
            return Err(RedactError::UnsupportedFormat { extension: ext });
        }
    }

    let color = parse_fill_color(fill_color)?;

    let mut img = image_crate::open(input).map_err(|e| RedactError::ImageLoad {
        path: input.to_path_buf(),
        source: e.to_string(),
    })?;

    for region in regions {
        draw_filled_rect(&mut img, region, color);
    }

    // JPEG doesn't support RGBA — convert to RGB before saving.
    let saveable: image_crate::DynamicImage = match ext.as_str() {
        "jpg" | "jpeg" => image_crate::DynamicImage::ImageRgb8(img.to_rgb8()),
        _ => img,
    };

    saveable.save(output).map_err(|e| RedactError::ImageSave {
        path: output.to_path_buf(),
        source: e.to_string(),
    })?;

    Ok(())
}
