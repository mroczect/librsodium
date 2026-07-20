use crate::handler::types::LibrsodiumResponse;
use crate::handler::error::SodiumError;

pub fn version_string() -> LibrsodiumResponse<String> {
    let s = libsodium_rs::version::version_string().to_owned();
    if s.is_empty() {
        return LibrsodiumResponse::err(
            SodiumError::Operation("Version string is empty".into()).into(),
        );
    }
    LibrsodiumResponse::ok(s)
}

pub fn library_version_major() -> LibrsodiumResponse<i32> {
    let v = libsodium_rs::version::library_version_major();
    if v < 0 {
        return LibrsodiumResponse::err(
            SodiumError::Operation("Major version is negative".into()).into(),
        );
    }
    LibrsodiumResponse::ok(v)
}

pub fn library_version_minor() -> LibrsodiumResponse<i32> {
    let v = libsodium_rs::version::library_version_minor();
    if v < 0 {
        return LibrsodiumResponse::err(
            SodiumError::Operation("Minor version is negative".into()).into(),
        );
    }
    LibrsodiumResponse::ok(v)
}

pub fn library_minimal() -> LibrsodiumResponse<bool> {
    LibrsodiumResponse::ok(libsodium_rs::version::library_minimal())
}