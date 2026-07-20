use librsodium::core::version;
use librsodium::init;

#[ctor::ctor(unsafe)]
fn initialize() {
    init().expect("libsodium init failed");
}

#[test]
fn version_string_not_empty() {
    let s = version::version_string().expect("version_string should succeed");
    assert!(!s.is_empty(), "Version string must not be empty");
}

#[test]
fn version_major_not_negative() {
    let major = version::library_version_major().expect("library_version_major should succeed");
    assert!(major >= 0, "Major version must be >= 0");
}

#[test]
fn version_minor_not_negative() {
    let minor = version::library_version_minor().expect("library_version_minor should succeed");
    assert!(minor >= 0, "Minor version must be >= 0");
}

#[test]
fn version_minimal_returns_bool() {
    let minimal = version::library_minimal().expect("library_minimal should succeed");
    let _: bool = minimal;
}
