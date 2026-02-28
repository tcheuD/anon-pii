use super::*;
use crate::image_redact::redact;
use image_crate::DynamicImage;
use image_crate::Rgba;
use std::path::Path;

fn white_image(w: u32, h: u32) -> DynamicImage {
    DynamicImage::ImageRgba8(image_crate::RgbaImage::from_pixel(
        w,
        h,
        Rgba([255, 255, 255, 255]),
    ))
}

fn region(x: u32, y: u32, w: u32, h: u32) -> RedactionRegion {
    RedactionRegion {
        x,
        y,
        width: w,
        height: h,
        entity_type: "TEST".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Color parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_named_colors() {
    let cases = [
        ("black", [0, 0, 0, 255]),
        ("white", [255, 255, 255, 255]),
        ("red", [255, 0, 0, 255]),
        ("green", [0, 128, 0, 255]),
        ("blue", [0, 0, 255, 255]),
        ("yellow", [255, 255, 0, 255]),
        ("magenta", [255, 0, 255, 255]),
        ("cyan", [0, 255, 255, 255]),
        ("gray", [128, 128, 128, 255]),
        ("grey", [128, 128, 128, 255]),
    ];
    for (name, expected) in &cases {
        assert_eq!(
            redact::parse_fill_color(name).unwrap(),
            *expected,
            "failed for color name: {name}"
        );
    }
}

#[test]
fn parse_case_insensitive() {
    assert_eq!(redact::parse_fill_color("BLACK").unwrap(), [0, 0, 0, 255]);
    assert_eq!(redact::parse_fill_color("Black").unwrap(), [0, 0, 0, 255]);
}

#[test]
fn parse_hex_6_digit() {
    assert_eq!(
        redact::parse_fill_color("#FF0000").unwrap(),
        [255, 0, 0, 255]
    );
}

#[test]
fn parse_hex_6_lowercase() {
    assert_eq!(
        redact::parse_fill_color("#ff0000").unwrap(),
        [255, 0, 0, 255]
    );
}

#[test]
fn parse_hex_3_digit() {
    assert_eq!(redact::parse_fill_color("#F00").unwrap(), [255, 0, 0, 255]);
}

#[test]
fn parse_hex_3_mixed() {
    assert_eq!(
        redact::parse_fill_color("#AbC").unwrap(),
        [170, 187, 204, 255]
    );
}

#[test]
fn parse_hex_black() {
    assert_eq!(redact::parse_fill_color("#000000").unwrap(), [0, 0, 0, 255]);
    assert_eq!(redact::parse_fill_color("#000").unwrap(), [0, 0, 0, 255]);
}

#[test]
fn parse_invalid_name() {
    let result = redact::parse_fill_color("purple");
    assert!(matches!(result, Err(redact::RedactError::InvalidColor(_))));
}

#[test]
fn parse_invalid_hex_length() {
    let result = redact::parse_fill_color("#FFFF");
    assert!(matches!(result, Err(redact::RedactError::InvalidColor(_))));
}

#[test]
fn parse_invalid_hex_chars() {
    let result = redact::parse_fill_color("#GGGGGG");
    assert!(matches!(result, Err(redact::RedactError::InvalidColor(_))));
}

#[test]
fn parse_empty() {
    let result = redact::parse_fill_color("");
    assert!(matches!(result, Err(redact::RedactError::InvalidColor(_))));
}

#[test]
fn parse_no_hash() {
    let result = redact::parse_fill_color("FF0000");
    assert!(matches!(result, Err(redact::RedactError::InvalidColor(_))));
}

// ---------------------------------------------------------------------------
// Image redaction tests
// ---------------------------------------------------------------------------

fn test_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anon_test_{}_{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn save_white_png(dir: &Path, w: u32, h: u32) -> std::path::PathBuf {
    let path = dir.join("input.png");
    white_image(w, h).save(&path).unwrap();
    path
}

#[test]
fn redact_single_region() {
    let dir = test_dir("single_region");
    let input = save_white_png(&dir, 100, 100);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[region(10, 10, 20, 20)], "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(15, 15), Rgba([0, 0, 0, 255]));
    assert_eq!(*img.get_pixel(5, 5), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_multiple_regions() {
    let dir = test_dir("multiple_regions");
    let input = save_white_png(&dir, 100, 100);
    let output = dir.join("output.png");

    let regions = vec![region(10, 10, 10, 10), region(50, 50, 10, 10)];
    redact::redact_image(&input, &output, &regions, "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(15, 15), Rgba([0, 0, 0, 255]));
    assert_eq!(*img.get_pixel(55, 55), Rgba([0, 0, 0, 255]));
    assert_eq!(*img.get_pixel(35, 35), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_region_beyond_bounds() {
    let dir = test_dir("beyond_bounds");
    let input = save_white_png(&dir, 100, 100);
    let output = dir.join("output.png");

    // Region starts at (90,90) and extends 20px past the 100×100 boundary.
    redact::redact_image(&input, &output, &[region(90, 90, 20, 20)], "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    // Pixel at (95,95) is inside bounds and inside the region — should be filled.
    assert_eq!(*img.get_pixel(95, 95), Rgba([0, 0, 0, 255]));
    // Pixel at (5,5) is outside the region — unchanged.
    assert_eq!(*img.get_pixel(5, 5), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_region_entirely_outside() {
    let dir = test_dir("entirely_outside");
    let input = save_white_png(&dir, 100, 100);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[region(200, 200, 10, 10)], "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(50, 50), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_zero_size_region() {
    let dir = test_dir("zero_size");
    let input = save_white_png(&dir, 100, 100);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[region(10, 10, 0, 10)], "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(10, 10), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_empty_regions() {
    let dir = test_dir("empty_regions");
    let input = save_white_png(&dir, 50, 50);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[], "black").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(25, 25), Rgba([255, 255, 255, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_full_image() {
    let dir = test_dir("full_image");
    let input = save_white_png(&dir, 50, 50);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[region(0, 0, 50, 50)], "red").unwrap();

    let img = image_crate::open(&output).unwrap().to_rgba8();
    assert_eq!(*img.get_pixel(0, 0), Rgba([255, 0, 0, 255]));
    assert_eq!(*img.get_pixel(25, 25), Rgba([255, 0, 0, 255]));
    assert_eq!(*img.get_pixel(49, 49), Rgba([255, 0, 0, 255]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_saves_png() {
    let dir = test_dir("saves_png");
    let input = save_white_png(&dir, 20, 20);
    let output = dir.join("output.png");

    redact::redact_image(&input, &output, &[region(0, 0, 5, 5)], "black").unwrap();

    assert!(output.exists());
    image_crate::open(&output).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_saves_jpg() {
    let dir = test_dir("saves_jpg");
    let input = save_white_png(&dir, 20, 20);
    let output = dir.join("output.jpg");

    redact::redact_image(&input, &output, &[region(0, 0, 5, 5)], "black").unwrap();

    assert!(output.exists());
    image_crate::open(&output).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_rejects_unsupported_format() {
    let dir = test_dir("unsupported_fmt");
    let input = save_white_png(&dir, 20, 20);
    let output = dir.join("output.gif");

    let err = redact::redact_image(&input, &output, &[region(0, 0, 5, 5)], "black").unwrap_err();
    assert!(matches!(err, redact::RedactError::UnsupportedFormat { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_input_not_found() {
    let dir = test_dir("not_found");
    let input = dir.join("nonexistent.png");
    let output = dir.join("output.png");

    let err = redact::redact_image(&input, &output, &[region(0, 0, 5, 5)], "black").unwrap_err();
    assert!(matches!(err, redact::RedactError::ImageLoad { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redact_no_exif_in_output() {
    let dir = test_dir("no_exif");
    let input = save_white_png(&dir, 20, 20);
    let output = dir.join("output.jpg");

    redact::redact_image(&input, &output, &[region(0, 0, 5, 5)], "black").unwrap();

    let bytes = std::fs::read(&output).unwrap();
    // APP1 marker (0xFF 0xE1) is used for EXIF data in JPEG files.
    let has_app1 = bytes.windows(2).any(|w| w == [0xFF, 0xE1]);
    assert!(!has_app1, "JPEG output should not contain EXIF APP1 marker");

    let _ = std::fs::remove_dir_all(&dir);
}
