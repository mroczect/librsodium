pub mod core;
pub mod handler;

pub use handler::error::SodiumError;
pub use handler::types::{ErrorBody, LibrsodiumResponse};

use std::sync::OnceLock;

static INIT: OnceLock<Result<(), SodiumError>> = OnceLock::new();

pub fn init() -> Result<(), SodiumError> {
    INIT.get_or_init(|| libsodium_rs::ensure_init().map_err(|e| SodiumError::Init(e.to_string())))
        .clone()
}
