use crate::handler::error::SodiumError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LibrsodiumResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl<T: Serialize> LibrsodiumResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn err(error: ErrorBody) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
    pub fn to_json(&self) -> Result<String, SodiumError> {
        serde_json::to_string(self)
            .map_err(|e| SodiumError::Operation(format!("JSON serialization failed: {}", e)))
    }
}

impl<T: Serialize> From<Result<T, SodiumError>> for LibrsodiumResponse<T> {
    fn from(result: Result<T, SodiumError>) -> Self {
        match result {
            Ok(data) => Self::ok(data),
            Err(e) => Self::err(e.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}
impl ErrorBody {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
