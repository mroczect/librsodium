use crate::SodiumError;
use libsodium_rs::crypto_core::salsa2012 as lib_salsa2012;

pub const INPUTBYTES: usize = lib_salsa2012::INPUTBYTES;
pub const KEYBYTES: usize = lib_salsa2012::KEYBYTES;
pub const CONSTBYTES: usize = lib_salsa2012::CONSTBYTES;
pub const OUTPUTBYTES: usize = lib_salsa2012::OUTPUTBYTES;

pub fn salsa2012(
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
    Ok(lib_salsa2012::salsa2012(input, key, constant)?)
}
