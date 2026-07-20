use crate::SodiumError;
use libsodium_rs::crypto_core::ristretto255 as lib_ristretto;

pub const BYTES: usize = 32;
pub const SCALARBYTES: usize = 32;
pub const NONREDUCEDSCALARBYTES: usize = 64;
pub const HASHBYTES: usize = 64;

pub fn is_valid_point(p: &[u8]) -> Result<bool, SodiumError> {
    crate::init()?;
    if p.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid point length: expected {BYTES}, got {}",
            p.len()
        )));
    }
    Ok(lib_ristretto::is_valid_point(p)?)
}

pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES || q.len() != BYTES {
        return Err(SodiumError::InvalidInput(
            "invalid point length: both points must be 32 bytes".into(),
        ));
    }
    Ok(lib_ristretto::add(p, q)?)
}

pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES || q.len() != BYTES {
        return Err(SodiumError::InvalidInput(
            "invalid point length: both points must be 32 bytes".into(),
        ));
    }
    Ok(lib_ristretto::sub(p, q)?)
}

pub fn random() -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    Ok(lib_ristretto::random()?)
}

pub fn from_hash(h: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if h.len() != HASHBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid hash length: expected {HASHBYTES}, got {}",
            h.len()
        )));
    }
    Ok(lib_ristretto::from_hash(h)?)
}

pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != NONREDUCEDSCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {NONREDUCEDSCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ristretto::scalar_reduce(s)?)
}

pub fn scalar_random() -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    Ok(lib_ristretto::scalar_random())
}

pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ristretto::scalar_invert(s)?)
}

pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ristretto::scalar_negate(s)?)
}

pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    Ok(lib_ristretto::scalar_complement(s)?)
}

pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ristretto::scalar_add(x, y)?)
}

pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ristretto::scalar_sub(x, y)?)
}

pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(
            "invalid scalar length: both scalars must be 32 bytes".into(),
        ));
    }
    Ok(lib_ristretto::scalar_mul(x, y)?)
}
