//! Integration test for xlsx feature scaffold.

#[cfg(feature = "xlsx")]
#[test]
fn xlsx_module_is_accessible() {
    #[allow(unused_imports)]
    use anon_pii::xlsx as _;
}

#[cfg(feature = "xlsx")]
#[test]
fn format_xlsx_variant_exists() {
    use anon_pii::cli::Format;
    let _format = Format::Xlsx;
}

#[cfg(feature = "xlsx")]
#[test]
fn xlsx_detect_functions_accessible() {
    use anon_pii::xlsx::detect::{is_xlsx_bytes, is_xlsx_extension};
    use std::path::Path;

    assert!(!is_xlsx_bytes(&[]));
    assert!(is_xlsx_extension(Path::new("test.xlsx")));
}
