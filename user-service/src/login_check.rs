use actix_web::{
    body::BoxBody,
    http::header::{ToStrError, AUTHORIZATION},
    http::StatusCode,
    HttpRequest, HttpResponse, ResponseError,
};

use crate::{
    error::AppErrorResponse,
    jwt::{Claims, JwtService, JwtServiceError},
};

use derive_more::{Display, Error};

use jsonwebtoken::errors::ErrorKind as JWTErrorKind;

#[derive(Debug, Display, Error)]
pub(crate) enum LoginCheckError {
    #[display(fmt = "Authorization header is missing!")]
    NoAuthHeader,
    AuthHeaderDecodeError(ToStrError),
    JwtServiceError(JwtServiceError),
    NoBearer,
}

impl From<ToStrError> for LoginCheckError {
    fn from(value: ToStrError) -> Self {
        Self::AuthHeaderDecodeError(value)
    }
}

impl From<JwtServiceError> for LoginCheckError {
    fn from(value: JwtServiceError) -> Self {
        Self::JwtServiceError(value)
    }
}

impl ResponseError for LoginCheckError {
    fn status_code(&self) -> StatusCode {
        match self {
            LoginCheckError::NoAuthHeader => StatusCode::UNAUTHORIZED,
            LoginCheckError::JwtServiceError(JwtServiceError::JsonWebTokenError(e)) => {
                match e.kind() {
                    JWTErrorKind::InvalidToken
                    | JWTErrorKind::ImmatureSignature
                    | JWTErrorKind::ExpiredSignature => StatusCode::FORBIDDEN,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                }
            }
            LoginCheckError::NoBearer => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let message = self.to_string();
        let timestamp = time::OffsetDateTime::now_utc();

        HttpResponse::build(self.status_code()).json(AppErrorResponse { message, timestamp })
    }
}

static BEARER: &str = "Bearer ";

pub(crate) async fn get_logged_in_user_claims(
    req: &HttpRequest,
    jwt: JwtService,
) -> Result<Claims, LoginCheckError> {
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(LoginCheckError::NoAuthHeader)?
        .to_str()?
        .to_string();

    if !token.starts_with(BEARER) {
        return Err(LoginCheckError::NoBearer);
    };

    let token = token.trim_start_matches(BEARER);

    // check if access token is valid
    // if not, error out

    let decoded = jwt.decode(token)?;

    // TODO: Implement blacklist checking
    // check if access token is on blacklist
    // if it is, error out

    Ok(decoded.claims)
}
