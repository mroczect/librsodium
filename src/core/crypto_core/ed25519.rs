use crate::SodiumError;
use libsodium_rs::crypto_core::ed25519 as lib_ed25519;

pub const BYTES: usize = 32;
pub const SCALARBYTES: usize = 32;
pub const NONREDUCEDSCALARBYTES: usize = 64;
pub const UNIFORMBYTES: usize = 32;

pub fn is_valid_point(p: &[u8]) -> Result<bool, SodiumError> {
    crate::init()?;
    if p.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid point length: expected {BYTES}, got {}",
            p.len()
        )));
    }
    Ok(lib_ed25519::is_valid_point(p)?)
}

pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES || q.len() != BYTES {
        return Err(SodiumError::InvalidInput(
            "invalid point length: both points must be 32 bytes".into(),
        ));
    }
    Ok(lib_ed25519::add(p, q)?)
}

pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES || q.len() != BYTES {
        return Err(SodiumError::InvalidInput(
            "invalid point length: both points must be 32 bytes".into(),
        ));
    }
    Ok(lib_ed25519::sub(p, q)?)
}

pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != NONREDUCEDSCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {NONREDUCEDSCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ed25519::scalar_reduce(s)?)
}

pub fn random() -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    Ok(lib_ed25519::random())
}

pub fn scalar_random() -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    Ok(lib_ed25519::scalar_random())
}

pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ed25519::scalar_invert(s)?)
}

pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ed25519::scalar_negate(s)?)
}

pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ed25519::scalar_complement(s)?)
}

pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ed25519::scalar_add(x, y)?)
}

pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ed25519::scalar_sub(x, y)?)
}

pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ed25519::scalar_mul(x, y)?)
}

pub fn from_uniform(r: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if r.len() != UNIFORMBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid uniform string length: expected {UNIFORMBYTES}, got {}",
            r.len()
        )));
    }
    Ok(lib_ed25519::from_uniform(r)?)
}
