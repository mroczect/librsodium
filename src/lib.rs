pub mod core;
pub mod handler;

pub use handler::error::SodiumError;
pub use handler::types::{ErrorBody, LibrsodiumResponse};

pub fn init() -> Result<(), SodiumError> {
    libsodium_rs::ensure_init().map_err(|e| SodiumError::Init(e.to_string()))
}
