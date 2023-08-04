use actix_web::{body::BoxBody, http::StatusCode, post, HttpResponse, Responder, ResponseError};

use derive_more::{Display, Error};

use crate::login_check::LoginCheckError;

#[derive(Debug, Display, Error)]
pub(crate) enum LoginError {
    LoginCheckError(LoginCheckError),
}

impl ResponseError for LoginError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::LoginCheckError(e) => e.status_code(),
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::LoginCheckError(e) => e.error_response(),
        }
    }
}

#[post("login/password")]
pub(crate) async fn login_route() -> impl Responder {
    // TODO: Implement login
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    // get body
    // check if user exists
    // if doesn't exist, error out
    // generate access token JWT
    // store access token in database
    // generate refresh token
    // store refresh token in database
    // store refresh token in HttpOnly, Secure cookie
    // return access and refresh tokens

    "login not implemented"
}
