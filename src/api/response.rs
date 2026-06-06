use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "success".to_string(),
            data: Some(data),
            message: None,
        }
    }
}

impl ApiResponse<()> {
    pub fn ok() -> Self {
        Self {
            status: "success".to_string(),
            data: None,
            message: None,
        }
    }

    pub fn ok_with_message(msg: impl Into<String>) -> Self {
        Self {
            status: "success".to_string(),
            data: None,
            message: Some(msg.into()),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            data: None,
            message: Some(msg.into()),
        }
    }

    pub fn with_status(self, code: StatusCode) -> Response {
        (code, Json(self)).into_response()
    }
}
