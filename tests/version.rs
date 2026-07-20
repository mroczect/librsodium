use librsodium::core::version;
use librsodium::init;

#[ctor::ctor(unsafe)]
fn initialize() {
    init().expect("libsodium init failed");
}

#[test]
fn version_string_not_empty() {
    let res = version::version_string();
    assert!(res.success, "Version string must succeed");
    assert!(!res.data.unwrap().is_empty(), "Version string must not be empty");
}

#[test]
fn version_major_not_negative() {
    let res = version::library_version_major();
    assert!(res.success, "Major version must succeed");
    assert!(res.data.unwrap() >= 0, "Major version must be >= 0");
}

#[test]
fn version_minor_not_negative() {
    let res = version::library_version_minor();
    assert!(res.success, "Minor version must succeed");
    assert!(res.data.unwrap() >= 0, "Minor version must be >= 0");
}

#[test]
fn version_minimal_returns_bool() {
    let res = version::library_minimal();
    assert!(res.success, "Minimal check must succeed");
}