use crate::SodiumError;

pub fn bytes(size: usize) -> Result<Vec<u8>, SodiumError> {
    crate::init()?;
    if size == 0 {
        return Err(SodiumError::InvalidSize {
            expected: 1,
            got: 0,
        });
    }
    if size > 1_073_741_824 {
        return Err(SodiumError::InvalidSize {
            expected: 1_073_741_824,
            got: size,
        });
    }
    Ok(libsodium_rs::random::bytes(size))
}

pub fn fill_bytes(buf: &mut [u8]) -> Result<(), SodiumError> {
    crate::init()?;
    if buf.is_empty() {
        return Err(SodiumError::InvalidSize {
            expected: 1,
            got: 0,
        });
    }
    libsodium_rs::random::fill_bytes(buf);
    Ok(())
}

pub fn u32() -> Result<u32, SodiumError> {
    crate::init()?;
    Ok(libsodium_rs::random::u32())
}

pub fn uniform(upper_bound: u32) -> Result<u32, SodiumError> {
    crate::init()?;
    if upper_bound == 0 {
        return Err(SodiumError::InvalidInput("upper_bound must be > 0".into()));
    }
    Ok(libsodium_rs::random::uniform(upper_bound))
}
