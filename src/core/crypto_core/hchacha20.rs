use crate::SodiumError;
use libsodium_rs::crypto_core::hchacha20 as lib_hchacha20;

pub const INPUTBYTES: usize = lib_hchacha20::INPUTBYTES;
pub const KEYBYTES: usize = lib_hchacha20::KEYBYTES;
pub const CONSTBYTES: usize = lib_hchacha20::CONSTBYTES;
pub const OUTPUTBYTES: usize = lib_hchacha20::OUTPUTBYTES;

pub fn hchacha20(
    input: &[u8],
    key: &[u8],
    constant: Option<&[u8]>,
) -> Result<[u8; OUTPUTBYTES], SodiumError> {
    crate::init()?;

    if input.len() != INPUTBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid input length: expected {INPUTBYTES}, got {}",
            input.len()
        )));
    }
    if key.len() != KEYBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid key length: expected {KEYBYTES}, got {}",
            key.len()
        )));
    }
    if let Some(c) = constant
        && c.len() != CONSTBYTES
    {
        return Err(SodiumError::InvalidInput(format!(
            "invalid constant length: expected {CONSTBYTES}, got {}",
            c.len()
        )));
    }

    Ok(lib_hchacha20::hchacha20(input, key, constant)?)
}
