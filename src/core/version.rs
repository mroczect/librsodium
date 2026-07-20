use crate::SodiumError;

pub fn version_string() -> Result<String, SodiumError> {
    crate::init()?;
    let s = libsodium_rs::version::version_string().to_owned();
    if s.is_empty() {
        return Err(SodiumError::Operation("Version string is empty".into()));
    }
    Ok(s)
}

pub fn library_version_major() -> Result<i32, SodiumError> {
    crate::init()?;
    let v = libsodium_rs::version::library_version_major();
    if v < 0 {
        return Err(SodiumError::Operation("Major version is negative".into()));
    }
    Ok(v)
}

pub fn library_version_minor() -> Result<i32, SodiumError> {
    crate::init()?;
    let v = libsodium_rs::version::library_version_minor();
    if v < 0 {
        return Err(SodiumError::Operation("Minor version is negative".into()));
    }
    Ok(v)
}

pub fn library_minimal() -> Result<bool, SodiumError> {
    crate::init()?;
    Ok(libsodium_rs::version::library_minimal())
}
