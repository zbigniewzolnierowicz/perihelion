use std::cell::Cell;

use actix_web::{body::BoxBody, post, HttpRequest, HttpResponse, Responder, ResponseError, http::StatusCode};
use async_trait::async_trait;
use mockall::automock;
use serde_json::json;
use strum::Display;
use redis::Commands;

use crate::{
    login_check::{get_logged_in_user_claims, LoginCheckError},
    State, ACCESS_TOKEN_BLACKLIST_KEY,
};

struct RedisLogOutService(Cell<redis::Connection>);

#[async_trait]
#[automock]
trait LogOutService {
    async fn add_access_token(self, token: String) -> Result<bool, LogOutServiceError>;
}

#[derive(Debug)]
pub(crate) enum LogOutServiceError {
    RedisError(redis::RedisError),
}

impl From<redis::RedisError> for LogOutServiceError {
    fn from(value: redis::RedisError) -> Self {
        Self::RedisError(value)
    }
}

#[async_trait]
impl LogOutService for RedisLogOutService {
    async fn add_access_token(mut self, token: String) -> Result<bool, LogOutServiceError> {
        let conn = self.0.get_mut();

        let result = conn.sadd(ACCESS_TOKEN_BLACKLIST_KEY, token)?;

        Ok(result)
    }
}

#[derive(Debug, Display)]
pub(crate) enum LogOutError {
    InternalError,
    LogOutServiceError(LogOutServiceError),
    NotLoggedIn,
    LoginCheckError(LoginCheckError),
}

impl From<LogOutServiceError> for LogOutError {
    fn from(value: LogOutServiceError) -> Self {
        Self::LogOutServiceError(value)
    }
}

impl From<LoginCheckError> for LogOutError {
    fn from(value: LoginCheckError) -> Self {
        Self::LoginCheckError(value)
    }
}

impl ResponseError for LogOutError {
    fn status_code(&self) -> StatusCode {
        // TODO: replace with meaningful statuses
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code()).json("Logout Error")
    }
}

#[post("logout")]
pub(crate) async fn logout_route(state: State, req: HttpRequest) -> Result<String, LogOutError> {
    let jwt = state.jwt.clone();
    let service = RedisLogOutService(Cell::new(
        state
            .redis
            .get_connection()
            .map_err(|_| LogOutError::InternalError)?,
    ));

    // check if Authentication header has bearer token
    let (token, _) = get_logged_in_user_claims(&req, jwt, state.redis.clone()).await?;

    // add jwt to blacklist

    service
        .add_access_token(token)
        .await
        .map_err(LogOutError::from)?;

    // TODO: implement blacklist for refresh tokens
    // get current refresh token
    // add refresh token to blacklist

    Ok(json!({}).to_string())
}

#[post("logout/all")]
pub(crate) async fn logout_all_route(_state: State, _req: HttpRequest) -> impl Responder {
    // let jwt = state.jwt.clone();
    // let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout for all
    // get all jwt for current user
    // add jwts to blacklist
    // get all refresh tokens for current user
    // add refresh tokens to blacklist

    "implement logout all devices"
}

#[cfg(test)]
mod test {
    // TODO: Implement tests for logout
}
