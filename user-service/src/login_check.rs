use actix_web::{
    body::BoxBody,
    http::header::{ToStrError, AUTHORIZATION},
    http::StatusCode,
    HttpRequest, HttpResponse, ResponseError,
};
use redis::Commands;

use crate::{
    error::AppErrorResponse,
    jwt::{Claims, JwtService, JwtServiceError},
    ACCESS_TOKEN_BLACKLIST_KEY,
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
    RedisError(redis::RedisError),
    BlacklistedToken,
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

impl From<redis::RedisError> for LoginCheckError {
    fn from(value: redis::RedisError) -> Self {
        Self::RedisError(value)
    }
}

impl ResponseError for LoginCheckError {
    fn status_code(&self) -> StatusCode {
        match self {
            LoginCheckError::NoAuthHeader => StatusCode::UNAUTHORIZED,
            LoginCheckError::BlacklistedToken => StatusCode::FORBIDDEN,
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
    rclient: redis::Client,
) -> Result<(String, Claims), LoginCheckError> {
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(LoginCheckError::NoAuthHeader)?
        .to_str()?
        .to_string();
    let mut redis_conn = rclient.get_connection()?;

    if !token.starts_with(BEARER) {
        return Err(LoginCheckError::NoBearer);
    };

    let token = token.trim_start_matches(BEARER);

    // check if access token is valid
    // if not, error out

    let decoded = jwt.decode(token)?;

    // check if access token is on blacklist
    let access_token_is_in_blacklist: bool =
        redis_conn.sismember(ACCESS_TOKEN_BLACKLIST_KEY, token)?;

    if access_token_is_in_blacklist {
        return Err(LoginCheckError::BlacklistedToken);
    };

    // if it is, error out

    Ok((token.to_string(), decoded.claims))
}
