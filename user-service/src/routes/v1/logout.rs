use actix_web::{
    body::BoxBody, http::StatusCode, post, HttpRequest, HttpResponse, Responder, ResponseError,
};
use strum::Display;

use crate::{
    login_check::{get_logged_in_user_claims, LoginCheckError},
    State,
};

use super::{services::blacklist::BlacklistServiceError, UserServiceState};

#[derive(Debug, Display)]
pub(crate) enum LogOutError {
    InternalError,
    BlacklistServiceError(BlacklistServiceError),
    NotLoggedIn,
    LoginCheckError(LoginCheckError),
}

impl From<BlacklistServiceError> for LogOutError {
    fn from(value: BlacklistServiceError) -> Self {
        Self::BlacklistServiceError(value)
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

    service
        .add_access_token(token)
        .await
        .map_err(LogOutError::from)?;

    // TODO: implement blacklist for refresh tokens
    // get current refresh token
    // add refresh token to blacklist

    Ok(HttpResponse::build(StatusCode::OK).finish())
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
