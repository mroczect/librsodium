use crate::handler::error::SodiumError;
use crate::handler::types::LibrsodiumResponse;

pub fn bytes(size: usize) -> LibrsodiumResponse<Vec<u8>> {
    if size == 0 {
        return LibrsodiumResponse::err(
            SodiumError::InvalidSize {
                expected: 1,
                got: 0,
            }
            .into(),
        );
    }
    if size > 1_073_741_824 {
        return LibrsodiumResponse::err(
            SodiumError::InvalidSize {
                expected: 1_073_741_824,
                got: size,
            }
            .into(),
        );
    }
    LibrsodiumResponse::ok(libsodium_rs::random::bytes(size))
}

pub fn fill_bytes(buf: &mut [u8]) -> LibrsodiumResponse<()> {
    if buf.is_empty() {
        return LibrsodiumResponse::err(
            SodiumError::InvalidSize {
                expected: 1,
                got: 0,
            }
            .into(),
        );
    }
    libsodium_rs::random::fill_bytes(buf);
    LibrsodiumResponse::ok(())
}

pub fn u32() -> LibrsodiumResponse<u32> {
    LibrsodiumResponse::ok(libsodium_rs::random::u32())
}

pub fn uniform(upper_bound: u32) -> LibrsodiumResponse<u32> {
    if upper_bound == 0 {
        return LibrsodiumResponse::err(
            SodiumError::InvalidInput("upper_bound must be > 0".into()).into(),
        );
    }
    LibrsodiumResponse::ok(libsodium_rs::random::uniform(upper_bound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_ok() {
        let res = bytes(32);
        assert!(res.success);
        assert_eq!(res.data.unwrap().len(), 32);
    }

    #[test]
    fn bytes_zero_fails() {
        let res = bytes(0);
        assert!(!res.success);
    }

    #[test]
    fn fill_ok() {
        let mut buf = [0u8; 16];
        let res = fill_bytes(&mut buf);
        assert!(res.success);
    }

    #[test]
    fn fill_empty_fails() {
        let res = fill_bytes(&mut []);
        assert!(!res.success);
    }

    #[test]
    fn u32_ok() {
        let res = u32();
        assert!(res.success);
    }

    #[test]
    fn uniform_ok() {
        let res = uniform(100);
        assert!(res.success);
        assert!(res.data.unwrap() < 100);
    }

    #[test]
    fn uniform_zero_fails() {
        let res = uniform(0);
        assert!(!res.success);
    }
}
