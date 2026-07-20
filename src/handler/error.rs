use super::types::ErrorBody;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum SodiumError {
    #[error("Init failed: {0}")]
    Init(String),

    #[error("Library not initialized")]
    NotInitialized,

    #[error("Random generation failed: {0}")]
    Random(String),

    #[error("Invalid size: expected {expected}, got {got}")]
    InvalidSize { expected: usize, got: usize },

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Hashing failed: {0}")]
    Hashing(String),

    #[error("Password hashing failed: {0}")]
    PwHash(String),

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Operation failed: {0}")]
    Operation(String),

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for SodiumError {
    fn from(e: std::io::Error) -> Self {
        SodiumError::Io(e.to_string())
    }
}

impl From<libsodium_rs::SodiumError> for SodiumError {
    fn from(e: libsodium_rs::SodiumError) -> Self {
        match e {
            libsodium_rs::SodiumError::InvalidKey(m) => SodiumError::InvalidKey(m),
            libsodium_rs::SodiumError::InvalidNonce(m) => SodiumError::InvalidNonce(m),
            libsodium_rs::SodiumError::InvalidInput(m) => SodiumError::InvalidInput(m),
            libsodium_rs::SodiumError::EncryptionError(m) => SodiumError::Encryption(m),
            libsodium_rs::SodiumError::DecryptionError(m) => SodiumError::Decryption(m),
            libsodium_rs::SodiumError::OperationError(m) => SodiumError::Operation(m),
            _ => SodiumError::Operation(e.to_string()),
        }
    }
}

impl From<SodiumError> for ErrorBody {
    fn from(e: SodiumError) -> Self {
        match e {
            SodiumError::Init(m) => ErrorBody::new("INIT_FAILED", m),
            SodiumError::NotInitialized => {
                ErrorBody::new("NOT_INITIALIZED", "Library not initialized")
            }
            SodiumError::Random(m) => ErrorBody::new("RANDOM_FAILED", m),
            SodiumError::InvalidSize { expected, got } => {
                ErrorBody::new("INVALID_SIZE", format!("expected {expected}, got {got}"))
            }
            SodiumError::InvalidKey(m) => ErrorBody::new("INVALID_KEY", m),
            SodiumError::InvalidNonce(m) => ErrorBody::new("INVALID_NONCE", m),
            SodiumError::InvalidInput(m) => ErrorBody::new("INVALID_INPUT", m),
            SodiumError::Encryption(m) => ErrorBody::new("ENCRYPTION_FAILED", m),
            SodiumError::Decryption(m) => ErrorBody::new("DECRYPTION_FAILED", m),
            SodiumError::Signing(m) => ErrorBody::new("SIGNING_FAILED", m),
            SodiumError::Verification(m) => ErrorBody::new("VERIFICATION_FAILED", m),
            SodiumError::Hashing(m) => ErrorBody::new("HASHING_FAILED", m),
            SodiumError::PwHash(m) => ErrorBody::new("PWHASH_FAILED", m),
            SodiumError::KeyExchange(m) => ErrorBody::new("KEY_EXCHANGE_FAILED", m),
            SodiumError::KeyDerivation(m) => ErrorBody::new("KEY_DERIVATION_FAILED", m),
            SodiumError::Operation(m) => ErrorBody::new("OPERATION_FAILED", m),
            SodiumError::Io(m) => ErrorBody::new("IO_ERROR", m),
        }
    }
}
