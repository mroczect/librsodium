use crate::SodiumError;

pub const BYTES: usize = libsodium_sys::crypto_core_ed25519_BYTES as usize;
pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ed25519_SCALARBYTES as usize;
pub const NONREDUCEDSCALARBYTES: usize =
    libsodium_sys::crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;
pub const UNIFORMBYTES: usize = libsodium_sys::crypto_core_ed25519_UNIFORMBYTES as usize;

pub fn is_valid_point(p: &[u8]) -> Result<bool, SodiumError> {
    crate::init()?;
    if p.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid point length: expected {BYTES}, got {}",
            p.len()
        )));
    }
    Ok(unsafe { libsodium_sys::crypto_core_ed25519_is_valid_point(p.as_ptr()) == 1 })
}

pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid first point length: expected {BYTES}, got {}",
            p.len()
        )));
    }
    if q.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid second point length: expected {BYTES}, got {}",
            q.len()
        )));
    }
    let mut r = [0u8; BYTES];
    if unsafe { libsodium_sys::crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
        != 0
    {
        return Err(SodiumError::Operation("point addition failed".into()));
    }
    Ok(r)
}

pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if p.len() != BYTES || q.len() != BYTES {
        return Err(SodiumError::InvalidInput(
            "invalid point length: both points must be 32 bytes".into(),
        ));
    }
    let mut r = [0u8; BYTES];
    if unsafe { libsodium_sys::crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
        != 0
    {
        return Err(SodiumError::Operation("point subtraction failed".into()));
    }
    Ok(r)
}

pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != NONREDUCEDSCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {NONREDUCEDSCALARBYTES}, got {}",
            s.len()
        )));
    }
    let mut r = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_reduce(r.as_mut_ptr(), s.as_ptr()) };
    Ok(r)
}

pub fn random() -> [u8; BYTES] {
    let mut p = [0u8; BYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_random(p.as_mut_ptr()) };
    p
}

pub fn scalar_random() -> [u8; SCALARBYTES] {
    let mut r = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_random(r.as_mut_ptr()) };
    r
}

pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    let mut recip = [0u8; SCALARBYTES];
    let result = unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_invert(recip.as_mut_ptr(), s.as_ptr())
    };
    if result != 0 {
        return Err(SodiumError::Operation(
            "scalar inversion failed (scalar may be 0)".into(),
        ));
    }
    Ok(recip)
}

pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    let mut neg = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_negate(neg.as_mut_ptr(), s.as_ptr()) };
    Ok(neg)
}

pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if s.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {SCALARBYTES}, got {}",
            s.len()
        )));
    }
    let mut comp = [0u8; SCALARBYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_complement(comp.as_mut_ptr(), s.as_ptr())
    };
    Ok(comp)
}

pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid first scalar length: expected {SCALARBYTES}, got {}",
            x.len()
        )));
    }
    if y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid second scalar length: expected {SCALARBYTES}, got {}",
            y.len()
        )));
    }
    let mut z = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_add(z.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    Ok(z)
}

pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid first scalar length: expected {SCALARBYTES}, got {}",
            x.len()
        )));
    }
    if y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid second scalar length: expected {SCALARBYTES}, got {}",
            y.len()
        )));
    }
    let mut z = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_sub(z.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    Ok(z)
}

pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES], SodiumError> {
    crate::init()?;
    if x.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid first scalar length: expected {SCALARBYTES}, got {}",
            x.len()
        )));
    }
    if y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid second scalar length: expected {SCALARBYTES}, got {}",
            y.len()
        )));
    }
    let mut z = [0u8; SCALARBYTES];
    unsafe { libsodium_sys::crypto_core_ed25519_scalar_mul(z.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    Ok(z)
}

pub fn from_uniform(r: &[u8]) -> Result<[u8; BYTES], SodiumError> {
    crate::init()?;
    if r.len() != UNIFORMBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid uniform string length: expected {UNIFORMBYTES}, got {}",
            r.len()
        )));
    }
    let mut p = [0u8; BYTES];
    let result =
        unsafe { libsodium_sys::crypto_core_ed25519_from_uniform(p.as_mut_ptr(), r.as_ptr()) };
    if result != 0 {
        return Err(SodiumError::Operation(
            "conversion from uniform string failed".into(),
        ));
    }
    Ok(p)
}