use crate::{
    jwt::JwtServiceError,
    v1::{LoginError, SignupError},
};
use actix_web::{body::BoxBody, http::StatusCode, HttpResponse, ResponseError};
use derive_more::Display;
use jsonwebtoken::errors::ErrorKind as JWTErrorKind;
use serde::{Deserialize, Serialize};

#[derive(Display, Debug)]
pub(crate) enum AppError {
    LoginError(LoginError),
    SignupError(SignupError),
}

#[derive(Serialize, Deserialize)]
struct AppErrorResponse {
    message: String,
    timestamp: time::OffsetDateTime,
}

impl From<SignupError> for AppError {
    fn from(value: SignupError) -> Self {
        Self::SignupError(value)
    }
}

impl From<LoginError> for AppError {
    fn from(value: LoginError) -> Self {
        Self::LoginError(value)
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::LoginError(LoginError::NoAuthHeader) => StatusCode::UNAUTHORIZED,
            AppError::LoginError(LoginError::JwtServiceError(
                JwtServiceError::JsonWebTokenError(e),
            )) => match e.kind() {
                JWTErrorKind::InvalidToken
                | JWTErrorKind::ImmatureSignature
                | JWTErrorKind::ExpiredSignature => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::SignupError(SignupError::AlreadyLoggedIn) => StatusCode::FORBIDDEN,
            AppError::SignupError(SignupError::AlreadyExists) => StatusCode::CONFLICT,
            AppError::SignupError(SignupError::ValidationError(_)) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let message = match self {
            AppError::LoginError(e) => e.to_string(),
            AppError::SignupError(e) => e.to_string(),
        };

        let timestamp = time::OffsetDateTime::now_utc();

        HttpResponse::build(self.status_code()).json(AppErrorResponse { message, timestamp })
    }
}

pub(crate) type AppResult<T> = Result<T, AppError>;
