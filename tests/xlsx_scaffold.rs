//! Integration test for xlsx feature scaffold.

#[cfg(feature = "xlsx")]
#[test]
fn xlsx_module_is_accessible() {
    #[allow(unused_imports)]
    use anon::xlsx as _;
}
