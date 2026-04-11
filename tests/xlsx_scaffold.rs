//! Integration test for xlsx feature scaffold.

#[cfg(feature = "xlsx")]
#[test]
fn xlsx_module_is_accessible() {
    #[allow(unused_imports)]
    use anon::xlsx as _;
}

#[cfg(feature = "xlsx")]
#[test]
fn format_xlsx_variant_exists() {
    use anon::cli::Format;
    let _format = Format::Xlsx;
}

#[cfg(feature = "xlsx")]
#[test]
fn xlsx_detect_functions_accessible() {
    use anon::xlsx::detect::{is_xlsx_bytes, is_xlsx_extension};
    use std::path::Path;

    assert!(!is_xlsx_bytes(&[]));
    assert!(is_xlsx_extension(Path::new("test.xlsx")));
}
