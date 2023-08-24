use actix_web::{body::BoxBody, http::StatusCode, post, HttpRequest, HttpResponse, ResponseError};
use strum::Display;

use crate::{
    jwt::Claims,
    login_check::{get_logged_in_user_claims, LoginCheckError},
    State, REFRESH_TOKEN_COOKIE,
};

use super::{services::blacklist::BlacklistServiceError, UserServiceState};

#[derive(Debug, Display)]
pub(crate) enum LogOutError {
    BlacklistService(BlacklistServiceError),
    LoginCheck(LoginCheckError),
    Database(sqlx::Error),
}

impl From<BlacklistServiceError> for LogOutError {
    fn from(value: BlacklistServiceError) -> Self {
        Self::BlacklistService(value)
    }
}

impl From<LoginCheckError> for LogOutError {
    fn from(value: LoginCheckError) -> Self {
        Self::LoginCheck(value)
    }
}
impl From<sqlx::Error> for LogOutError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl ResponseError for LogOutError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::LoginCheck(e) => e.status_code(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code()).json("Logout Error")
    }
}

#[post("logout")]
pub(crate) async fn logout_route(
    state: State,
    user_service_state: UserServiceState,
    req: HttpRequest,
) -> Result<HttpResponse, LogOutError> {
    let jwt = &state.jwt;
    let mut service = user_service_state.blacklist_service.lock().await;

    // check if Authentication header has bearer token
    let (token, _) = get_logged_in_user_claims(&req, jwt, service.as_mut()).await?;

    // add jwt to blacklist

    service.add_access_token(token).map_err(LogOutError::from)?;

    // get current refresh token
    if let Some(refresh_cookie) = req.cookie(REFRESH_TOKEN_COOKIE) {
        // add refresh token to blacklist
        service.add_refresh_token(refresh_cookie.to_string())?;
    }

    Ok(HttpResponse::build(StatusCode::OK).finish())
}

#[post("logout/all")]
pub(crate) async fn logout_all_route(
    state: State,
    user_service_state: UserServiceState,
    req: HttpRequest,
) -> Result<HttpResponse, LogOutError> {
    let jwt = &state.jwt;
    let db = &state.db;
    let mut blacklist = user_service_state.blacklist_service.lock().await;
    let (_, Claims { sub: id, .. }) =
        get_logged_in_user_claims(&req, jwt, blacklist.as_mut()).await?;

    // get all jwt for current user
    let all_jwt_for_current_user: Vec<String> =
        sqlx::query!("SELECT content FROM jwt WHERE user_id = $1", id)
            .fetch_all(db)
            .await?
            .iter()
            .map(|val| val.content.clone())
            .collect();

    // add jwts to blacklist
    blacklist.add_access_tokens(all_jwt_for_current_user)?;

    // get all refresh tokens for current user
    let all_refresh_for_current_user: Vec<String> =
        sqlx::query!("SELECT content FROM refresh WHERE user_id = $1", id)
            .fetch_all(db)
            .await?
            .iter()
            .map(|val| val.content.clone())
            .collect();

    // add refresh tokens to blacklist
    blacklist.add_refresh_tokens(all_refresh_for_current_user)?;

    Ok(HttpResponse::build(StatusCode::OK).finish())
}

#[cfg(test)]
mod test {
    // TODO: Implement tests for logout
}
