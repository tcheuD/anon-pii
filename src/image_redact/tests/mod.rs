use super::*;

mod ocr;
mod region;

#[test]
fn image_config_default_values() {
    let config = ImageConfig::default();
    assert!((config.threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.fill_color, "black");
    assert_eq!(config.padding, 2);
}
