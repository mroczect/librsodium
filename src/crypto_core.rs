//! ensure_init().expect("Failed to initialize libsodium");
use crate::{Result, SodiumError};

pub mod ed25519 {
    use super::*;

    pub const BYTES: usize = libsodium_sys::crypto_core_ed25519_BYTES as usize;
    pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ed25519_SCALARBYTES as usize;
    pub const NONREDUCEDSCALARBYTES: usize =
        libsodium_sys::crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;
    pub const UNIFORMBYTES: usize = libsodium_sys::crypto_core_ed25519_UNIFORMBYTES as usize;

    pub fn is_valid_point(p: &[u8]) -> Result<bool> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid point length: expected {}, got {}",
                BYTES,
                p.len()
            )));
        }
        Ok(unsafe { libsodium_sys::crypto_core_ed25519_is_valid_point(p.as_ptr()) == 1 })
    }

    pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first point length: expected {}, got {}",
                BYTES,
                p.len()
            )));
        }
        if q.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second point length: expected {}, got {}",
                BYTES,
                q.len()
            )));
        }

        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError("point addition failed".into()));
        }
        Ok(r)
    }

    pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError(
                "point subtraction failed".into(),
            ));
        }
        Ok(r)
    }

    pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != NONREDUCEDSCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                NONREDUCEDSCALARBYTES,
                s.len()
            )));
        }

        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_reduce(r.as_mut_ptr(), s.as_ptr());
        }
        Ok(r)
    }

    pub fn random() -> [u8; BYTES] {
        let mut p = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_random(p.as_mut_ptr());
        }
        p
    }

    pub fn scalar_random() -> [u8; SCALARBYTES] {
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_random(r.as_mut_ptr());
        }
        r
    }

    pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut recip = [0u8; SCALARBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_invert(recip.as_mut_ptr(), s.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "scalar inversion failed (scalar may be 0)".into(),
            ));
        }

        Ok(recip)
    }

    pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut neg = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_negate(neg.as_mut_ptr(), s.as_ptr());
        }

        Ok(neg)
    }

    pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut comp = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_complement(comp.as_mut_ptr(), s.as_ptr());
        }

        Ok(comp)
    }

    pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_add(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_sub(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_mul(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    pub fn from_uniform(r: &[u8]) -> Result<[u8; BYTES]> {
        if r.len() != UNIFORMBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid uniform string length: expected {}, got {}",
                UNIFORMBYTES,
                r.len()
            )));
        }

        let mut p = [0u8; BYTES];
        let result =
            unsafe { libsodium_sys::crypto_core_ed25519_from_uniform(p.as_mut_ptr(), r.as_ptr()) };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "conversion from uniform string failed".into(),
            ));
        }

        Ok(p)
    }
}

pub mod ristretto255 {
    use super::*;

    pub const BYTES: usize = libsodium_sys::crypto_core_ristretto255_BYTES as usize;
    pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ristretto255_SCALARBYTES as usize;
    pub const NONREDUCEDSCALARBYTES: usize =
        libsodium_sys::crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize;
    pub const HASHBYTES: usize = libsodium_sys::crypto_core_ristretto255_HASHBYTES as usize;

    pub fn is_valid_point(p: &[u8]) -> Result<bool> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        Ok(unsafe { libsodium_sys::crypto_core_ristretto255_is_valid_point(p.as_ptr()) == 1 })
    }

    pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe {
            libsodium_sys::crypto_core_ristretto255_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
        } != 0
        {
            return Err(SodiumError::OperationError("point addition failed".into()));
        }
        Ok(r)
    }

    pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe {
            libsodium_sys::crypto_core_ristretto255_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
        } != 0
        {
            return Err(SodiumError::OperationError(
                "point subtraction failed".into(),
            ));
        }
        Ok(r)
    }

    pub fn random() -> Result<[u8; BYTES]> {
        let mut r = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_random(r.as_mut_ptr());
        }
        Ok(r)
    }

    pub fn from_hash(h: &[u8]) -> Result<[u8; BYTES]> {
        if h.len() != HASHBYTES {
            return Err(SodiumError::InvalidInput("invalid hash length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ristretto255_from_hash(r.as_mut_ptr(), h.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError("hash to point failed".into()));
        }
        Ok(r)
    }

    pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != NONREDUCEDSCALARBYTES {
            return Err(SodiumError::InvalidInput("invalid scalar length".into()));
        }
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_reduce(r.as_mut_ptr(), s.as_ptr());
        }
        Ok(r)
    }

    pub fn scalar_random() -> [u8; SCALARBYTES] {
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_random(r.as_mut_ptr());
        }
        r
    }

    pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut recip = [0u8; SCALARBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_invert(recip.as_mut_ptr(), s.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "scalar inversion failed (scalar may be 0)".into(),
            ));
        }

        Ok(recip)
    }

    pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut neg = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_negate(neg.as_mut_ptr(), s.as_ptr());
        }

        Ok(neg)
    }

    pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut comp = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_complement(
                comp.as_mut_ptr(),
                s.as_ptr(),
            );
        }

        Ok(comp)
    }

    pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_add(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }

    pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_sub(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }

    pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_mul(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }
}

pub mod hchacha20 {
    use super::*;

    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_hchacha20_INPUTBYTES as usize;
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_hchacha20_KEYBYTES as usize;
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_hchacha20_CONSTBYTES as usize;
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_hchacha20_OUTPUTBYTES as usize;

    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    pub fn keybytes() -> usize {
        KEYBYTES
    }

    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    pub fn hchacha20(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }
        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }
        if let Some(c) = constant {
            if c.len() != CONSTBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "invalid constant length: expected {}, got {}",
                    CONSTBYTES,
                    c.len()
                )));
            }
        }

        let mut out = [0u8; OUTPUTBYTES];
        if unsafe {
            libsodium_sys::crypto_core_hchacha20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                constant.map_or(std::ptr::null(), |c| c.as_ptr()),
            )
        } != 0
        {
            return Err(SodiumError::OperationError("hchacha20 failed".into()));
        }
        Ok(out)
    }
}

/// ensure_init().expect("Failed to initialize libsodium");
pub mod hsalsa20 {
    use super::*;

    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_INPUTBYTES as usize;
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_hsalsa20_KEYBYTES as usize;
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_CONSTBYTES as usize;
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_OUTPUTBYTES as usize;

    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    pub fn keybytes() -> usize {
        KEYBYTES
    }

    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// ensure_init().expect("Failed to initialize libsodium");
    pub fn hsalsa20(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_hsalsa20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "hsalsa20 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// ensure_init().expect("Failed to initialize libsodium");
pub mod salsa2012 {
    use super::*;

    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa2012_INPUTBYTES as usize;
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa2012_KEYBYTES as usize;
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa2012_CONSTBYTES as usize;
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa2012_OUTPUTBYTES as usize;

    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    pub fn keybytes() -> usize {
        KEYBYTES
    }

    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// ensure_init().expect("Failed to initialize libsodium");
    pub fn salsa2012(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa2012(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa2012 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// ensure_init().expect("Failed to initialize libsodium");
pub mod salsa208 {
    use super::*;

    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa208_INPUTBYTES as usize;
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa208_KEYBYTES as usize;
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa208_CONSTBYTES as usize;
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa208_OUTPUTBYTES as usize;

    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    pub fn keybytes() -> usize {
        KEYBYTES
    }

    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// ensure_init().expect("Failed to initialize libsodium");
    pub fn salsa208(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa208(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa208 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// ensure_init().expect("Failed to initialize libsodium");
pub mod salsa20 {
    use super::*;

    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa20_INPUTBYTES as usize;
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa20_KEYBYTES as usize;
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa20_CONSTBYTES as usize;
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa20_OUTPUTBYTES as usize;

    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    pub fn keybytes() -> usize {
        KEYBYTES
    }

    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// ensure_init().expect("Failed to initialize libsodium");
    pub fn salsa20(input: &[u8], key: &[u8], constant: Option<&[u8]>) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa20 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

pub mod keccak1600 {
    pub const STATEBYTES: usize = 224;

    pub fn statebytes() -> usize {
        unsafe { libsodium_sys::crypto_core_keccak1600_statebytes() }
    }

    pub struct State {
        state: libsodium_sys::crypto_core_keccak1600_state,
    }

    impl State {
        pub fn new() -> Self {
            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
            };
            unsafe {
                libsodium_sys::crypto_core_keccak1600_init(&mut state.state);
            }
            state
        }

        pub fn init(&mut self) {
            unsafe {
                libsodium_sys::crypto_core_keccak1600_init(&mut self.state);
            }
        }

        pub fn xor_bytes(&mut self, bytes: &[u8], offset: usize) {
            assert!(
                offset + bytes.len() <= 200,
                "offset + length must be <= 200"
            );
            unsafe {
                libsodium_sys::crypto_core_keccak1600_xor_bytes(
                    &mut self.state,
                    bytes.as_ptr(),
                    offset,
                    bytes.len(),
                );
            }
        }

        pub fn extract_bytes(&self, bytes: &mut [u8], offset: usize) {
            assert!(
                offset + bytes.len() <= 200,
                "offset + length must be <= 200"
            );
            unsafe {
                libsodium_sys::crypto_core_keccak1600_extract_bytes(
                    &self.state,
                    bytes.as_mut_ptr(),
                    offset,
                    bytes.len(),
                );
            }
        }

        pub fn permute_24(&mut self) {
            unsafe {
                libsodium_sys::crypto_core_keccak1600_permute_24(&mut self.state);
            }
        }

        pub fn permute_12(&mut self) {
            unsafe {
                libsodium_sys::crypto_core_keccak1600_permute_12(&mut self.state);
            }
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clone for State {
        fn clone(&self) -> Self {
            let mut new_state = Self::new();
            new_state.state = self.state;
            new_state
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    #[test]
    fn test_ed25519_constants() {
        assert_eq!(ed25519::BYTES, 32);
        assert_eq!(ed25519::SCALARBYTES, 32);
        assert_eq!(ed25519::NONREDUCEDSCALARBYTES, 64);
        assert_eq!(ed25519::UNIFORMBYTES, 32);
    }

    #[test]
    fn test_ed25519_validation() {
        let valid_point = [0u8; ed25519::BYTES];
        assert!(!ed25519::is_valid_point(&valid_point).unwrap());

        let invalid_point = [0u8; ed25519::BYTES + 1];
        assert!(ed25519::is_valid_point(&invalid_point).is_err());

        let random_point = ed25519::random();
        assert!(ed25519::is_valid_point(&random_point).unwrap());
    }

    #[test]
    fn test_ed25519_point_operations() {
        let p = ed25519::random();
        let q = ed25519::random();

        let sum = ed25519::add(&p, &q).unwrap();
        assert_eq!(sum.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&sum).unwrap());

        let diff = ed25519::sub(&p, &q).unwrap();
        assert_eq!(diff.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&diff).unwrap());

        let uniform = random::bytes(ed25519::UNIFORMBYTES);
        let point = ed25519::from_uniform(&uniform).unwrap();
        assert_eq!(point.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&point).unwrap());
    }

    #[test]
    fn test_ed25519_scalar_operations() {
        let x = ed25519::scalar_random();
        let y = ed25519::scalar_random();
        assert_eq!(x.len(), ed25519::SCALARBYTES);
        assert_eq!(y.len(), ed25519::SCALARBYTES);

        let sum = ed25519::scalar_add(&x, &y).unwrap();
        assert_eq!(sum.len(), ed25519::SCALARBYTES);

        let diff = ed25519::scalar_sub(&x, &y).unwrap();
        assert_eq!(diff.len(), ed25519::SCALARBYTES);

        let product = ed25519::scalar_mul(&x, &y).unwrap();
        assert_eq!(product.len(), ed25519::SCALARBYTES);

        let neg = ed25519::scalar_negate(&x).unwrap();
        assert_eq!(neg.len(), ed25519::SCALARBYTES);

        let comp = ed25519::scalar_complement(&x).unwrap();
        assert_eq!(comp.len(), ed25519::SCALARBYTES);

        let mut non_zero = ed25519::scalar_random();
        non_zero[0] |= 1;
        let inv = ed25519::scalar_invert(&non_zero).unwrap();
        assert_eq!(inv.len(), ed25519::SCALARBYTES);

        let non_reduced = random::bytes(ed25519::NONREDUCEDSCALARBYTES);
        let reduced = ed25519::scalar_reduce(&non_reduced).unwrap();
        assert_eq!(reduced.len(), ed25519::SCALARBYTES);
    }

    #[test]
    fn test_ed25519_scalar_arithmetic_properties() {
        let x = ed25519::scalar_random();
        let y = ed25519::scalar_random();
        let z = ed25519::scalar_random();

        let sum1 = ed25519::scalar_add(&x, &y).unwrap();
        let sum1_z = ed25519::scalar_add(&sum1, &z).unwrap();

        let sum2 = ed25519::scalar_add(&y, &z).unwrap();
        let x_sum2 = ed25519::scalar_add(&x, &sum2).unwrap();

        assert_eq!(sum1_z, x_sum2);

        let xy = ed25519::scalar_add(&x, &y).unwrap();
        let yx = ed25519::scalar_add(&y, &x).unwrap();
        assert_eq!(xy, yx);

        let y_plus_z = ed25519::scalar_add(&y, &z).unwrap();
        let x_times_yz = ed25519::scalar_mul(&x, &y_plus_z).unwrap();

        let xy = ed25519::scalar_mul(&x, &y).unwrap();
        let xz = ed25519::scalar_mul(&x, &z).unwrap();
        let xy_plus_xz = ed25519::scalar_add(&xy, &xz).unwrap();

        assert_eq!(x_times_yz, xy_plus_xz);

        let neg_x = ed25519::scalar_negate(&x).unwrap();
        let x_plus_negx = ed25519::scalar_add(&x, &neg_x).unwrap();

        let zero_times_y = ed25519::scalar_mul(&x_plus_negx, &y).unwrap();
        let y_times_zero = ed25519::scalar_mul(&y, &x_plus_negx).unwrap();
        assert_eq!(zero_times_y, y_times_zero);
    }

    #[test]
    fn test_ristretto255_operations() {
        let point = ristretto255::random().unwrap();
        assert_eq!(point.len(), ristretto255::BYTES);
        assert!(ristretto255::is_valid_point(&point).unwrap());

        let point2 = ristretto255::random().unwrap();
        let sum = ristretto255::add(&point, &point2).unwrap();
        assert_eq!(sum.len(), ristretto255::BYTES);
        assert!(ristretto255::is_valid_point(&sum).unwrap());
    }

    #[test]
    fn test_ristretto255_scalar_operations() {
        let scalar1 = ristretto255::scalar_random();
        let scalar2 = ristretto255::scalar_random();
        assert_eq!(scalar1.len(), ristretto255::SCALARBYTES);
        assert_eq!(scalar2.len(), ristretto255::SCALARBYTES);

        let sum = ristretto255::scalar_add(&scalar1, &scalar2).unwrap();
        assert_eq!(sum.len(), ristretto255::SCALARBYTES);

        let diff = ristretto255::scalar_sub(&scalar1, &scalar2).unwrap();
        assert_eq!(diff.len(), ristretto255::SCALARBYTES);

        let product = ristretto255::scalar_mul(&scalar1, &scalar2).unwrap();
        assert_eq!(product.len(), ristretto255::SCALARBYTES);

        let neg = ristretto255::scalar_negate(&scalar1).unwrap();
        assert_eq!(neg.len(), ristretto255::SCALARBYTES);

        let comp = ristretto255::scalar_complement(&scalar1).unwrap();
        assert_eq!(comp.len(), ristretto255::SCALARBYTES);

        let mut non_zero = ristretto255::scalar_random();
        non_zero[0] |= 1;
        let inv = ristretto255::scalar_invert(&non_zero).unwrap();
        assert_eq!(inv.len(), ristretto255::SCALARBYTES);

        let non_reduced = random::bytes(ristretto255::NONREDUCEDSCALARBYTES);
        let reduced = ristretto255::scalar_reduce(&non_reduced).unwrap();
        assert_eq!(reduced.len(), ristretto255::SCALARBYTES);
    }

    #[test]
    fn test_ristretto255_scalar_arithmetic_properties() {
        let x = ristretto255::scalar_random();
        let y = ristretto255::scalar_random();
        let z = ristretto255::scalar_random();

        let sum1 = ristretto255::scalar_add(&x, &y).unwrap();
        let sum1_z = ristretto255::scalar_add(&sum1, &z).unwrap();

        let sum2 = ristretto255::scalar_add(&y, &z).unwrap();
        let x_sum2 = ristretto255::scalar_add(&x, &sum2).unwrap();

        assert_eq!(sum1_z, x_sum2);

        let xy = ristretto255::scalar_add(&x, &y).unwrap();
        let yx = ristretto255::scalar_add(&y, &x).unwrap();
        assert_eq!(xy, yx);

        let y_plus_z = ristretto255::scalar_add(&y, &z).unwrap();
        let x_times_yz = ristretto255::scalar_mul(&x, &y_plus_z).unwrap();

        let xy_prod = ristretto255::scalar_mul(&x, &y).unwrap();
        let xz_prod = ristretto255::scalar_mul(&x, &z).unwrap();
        let xy_plus_xz = ristretto255::scalar_add(&xy_prod, &xz_prod).unwrap();

        assert_eq!(x_times_yz, xy_plus_xz);

        let neg_x = ristretto255::scalar_negate(&x).unwrap();
        let x_plus_negx = ristretto255::scalar_add(&x, &neg_x).unwrap();

        let zero_times_y = ristretto255::scalar_mul(&x_plus_negx, &y).unwrap();
        let y_times_zero = ristretto255::scalar_mul(&y, &x_plus_negx).unwrap();
        assert_eq!(zero_times_y, y_times_zero);
    }

    #[test]
    fn test_ristretto255_scalar_inversion() {
        let mut scalar = ristretto255::scalar_random();
        scalar[0] |= 1;

        let inverse = ristretto255::scalar_invert(&scalar).unwrap();

        let product = ristretto255::scalar_mul(&scalar, &inverse).unwrap();

        assert_eq!(product[0], 1);
        for &byte in product.iter().take(ristretto255::SCALARBYTES).skip(1) {
            assert_eq!(byte, 0);
        }

        let zero = [0u8; ristretto255::SCALARBYTES];
        assert!(ristretto255::scalar_invert(&zero).is_err());
    }

    #[test]
    fn test_hchacha20() {
        let input = [0u8; hchacha20::INPUTBYTES];
        let key = [0u8; hchacha20::KEYBYTES];
        let result = hchacha20::hchacha20(&input, &key, None).unwrap();
        assert_eq!(result.len(), hchacha20::OUTPUTBYTES);

        let constant = [0u8; hchacha20::CONSTBYTES];
        let result_with_const = hchacha20::hchacha20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), hchacha20::OUTPUTBYTES);

        assert!(hchacha20::hchacha20(&[0u8; 1], &key, None).is_err());
        assert!(hchacha20::hchacha20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_hsalsa20() {
        let input = [0u8; hsalsa20::INPUTBYTES];
        let key = [0u8; hsalsa20::KEYBYTES];
        let result = hsalsa20::hsalsa20(&input, &key, None).unwrap();
        assert_eq!(result.len(), hsalsa20::OUTPUTBYTES);

        let constant = [0u8; hsalsa20::CONSTBYTES];
        let result_with_const = hsalsa20::hsalsa20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), hsalsa20::OUTPUTBYTES);

        assert!(hsalsa20::hsalsa20(&[0u8; 1], &key, None).is_err());
        assert!(hsalsa20::hsalsa20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa20() {
        let input = [0u8; salsa20::INPUTBYTES];
        let key = [0u8; salsa20::KEYBYTES];
        let result = salsa20::salsa20(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa20::OUTPUTBYTES);

        let constant = [0u8; salsa20::CONSTBYTES];
        let result_with_const = salsa20::salsa20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa20::OUTPUTBYTES);

        assert!(salsa20::salsa20(&[0u8; 1], &key, None).is_err());
        assert!(salsa20::salsa20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa2012() {
        let input = [0u8; salsa2012::INPUTBYTES];
        let key = [0u8; salsa2012::KEYBYTES];
        let result = salsa2012::salsa2012(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa2012::OUTPUTBYTES);

        let constant = [0u8; salsa2012::CONSTBYTES];
        let result_with_const = salsa2012::salsa2012(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa2012::OUTPUTBYTES);

        assert!(salsa2012::salsa2012(&[0u8; 1], &key, None).is_err());
        assert!(salsa2012::salsa2012(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa208() {
        let input = [0u8; salsa208::INPUTBYTES];
        let key = [0u8; salsa208::KEYBYTES];
        let result = salsa208::salsa208(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa208::OUTPUTBYTES);

        let constant = [0u8; salsa208::CONSTBYTES];
        let result_with_const = salsa208::salsa208(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa208::OUTPUTBYTES);

        assert!(salsa208::salsa208(&[0u8; 1], &key, None).is_err());
        assert!(salsa208::salsa208(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_keccak1600_constants() {
        assert_eq!(keccak1600::STATEBYTES, 224);
        assert_eq!(keccak1600::statebytes(), 224);
    }

    #[test]
    fn test_keccak1600_init() {
        let state = keccak1600::State::new();
        let _ = state;
    }

    #[test]
    fn test_keccak1600_xor_and_extract() {
        let mut state = keccak1600::State::new();

        let input = [0x42u8; 136];
        state.xor_bytes(&input, 0);

        let mut output = [0u8; 136];
        state.extract_bytes(&mut output, 0);

        assert_eq!(&output[..], &input[..]);
    }

    #[test]
    fn test_keccak1600_permute_24() {
        let mut state = keccak1600::State::new();

        let input = [0x01u8; 136];
        state.xor_bytes(&input, 0);

        let mut before = [0u8; 136];
        state.extract_bytes(&mut before, 0);

        state.permute_24();

        let mut after = [0u8; 136];
        state.extract_bytes(&mut after, 0);

        assert_ne!(&before[..], &after[..]);
    }

    #[test]
    fn test_keccak1600_permute_12() {
        let mut state = keccak1600::State::new();

        let input = [0x01u8; 136];
        state.xor_bytes(&input, 0);

        let mut before = [0u8; 136];
        state.extract_bytes(&mut before, 0);

        state.permute_12();

        let mut after = [0u8; 136];
        state.extract_bytes(&mut after, 0);

        assert_ne!(&before[..], &after[..]);
    }

    #[test]
    fn test_keccak1600_permute_24_vs_12() {
        let mut state24 = keccak1600::State::new();
        let mut state12 = keccak1600::State::new();

        let input = [0x01u8; 136];
        state24.xor_bytes(&input, 0);
        state12.xor_bytes(&input, 0);

        state24.permute_24();
        state12.permute_12();

        let mut out24 = [0u8; 136];
        let mut out12 = [0u8; 136];
        state24.extract_bytes(&mut out24, 0);
        state12.extract_bytes(&mut out12, 0);

        assert_ne!(&out24[..], &out12[..]);
    }

    #[test]
    fn test_keccak1600_clone() {
        let mut state1 = keccak1600::State::new();
        let input = [0x42u8; 100];
        state1.xor_bytes(&input, 0);
        state1.permute_24();

        let state2 = state1.clone();

        let mut out1 = [0u8; 100];
        let mut out2 = [0u8; 100];
        state1.extract_bytes(&mut out1, 0);
        state2.extract_bytes(&mut out2, 0);

        assert_eq!(&out1[..], &out2[..]);
    }

    #[test]
    fn test_keccak1600_reinit() {
        let mut state = keccak1600::State::new();

        let input = [0x42u8; 100];
        state.xor_bytes(&input, 0);
        state.permute_24();

        state.init();

        let mut output = [0u8; 100];
        state.extract_bytes(&mut output, 0);
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_keccak1600_offset() {
        let mut state = keccak1600::State::new();

        state.xor_bytes(&[0x01], 0);
        state.xor_bytes(&[0x02], 50);
        state.xor_bytes(&[0x03], 100);

        let mut out = [0u8; 1];
        state.extract_bytes(&mut out, 0);
        assert_eq!(out[0], 0x01);

        state.extract_bytes(&mut out, 50);
        assert_eq!(out[0], 0x02);

        state.extract_bytes(&mut out, 100);
        assert_eq!(out[0], 0x03);
    }

    #[test]
    #[should_panic(expected = "offset + length must be <= 200")]
    fn test_keccak1600_xor_overflow() {
        let mut state = keccak1600::State::new();
        let data = [0u8; 10];
        state.xor_bytes(&data, 195);
    }

    #[test]
    #[should_panic(expected = "offset + length must be <= 200")]
    fn test_keccak1600_extract_overflow() {
        let state = keccak1600::State::new();
        let mut data = [0u8; 10];
        state.extract_bytes(&mut data, 195);
    }
}
