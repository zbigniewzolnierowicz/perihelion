use actix_web::{
    get,
    http::header::{ToStrError, AUTHORIZATION},
    post, web, HttpRequest, Responder, Scope,
};

use crate::{
    error::{AppError, AppResult},
    jwt::{Claims, JwtService, JwtServiceError},
    State,
};

use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub(crate) enum LoginError {
    #[display(fmt = "Authorization header is missing!")]
    NoAuthHeader,
    AuthHeaderDecodeError(ToStrError),
    JwtServiceError(JwtServiceError),
}

impl From<ToStrError> for LoginError {
    fn from(value: ToStrError) -> Self {
        Self::AuthHeaderDecodeError(value)
    }
}

impl From<JwtServiceError> for LoginError {
    fn from(value: JwtServiceError) -> Self {
        Self::JwtServiceError(value)
    }
}

#[derive(Debug, Display, Error)]
pub(crate) enum SignupError {
    #[display(fmt = "User is already logged in.")]
    AlreadyLoggedIn,
}

pub(crate) async fn claims(req: &HttpRequest, jwt: JwtService) -> Result<Claims, LoginError> {
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(LoginError::NoAuthHeader)?
        .to_str()?
        .to_string();

    // check if access token is valid
    // if not, error out

    let decoded = jwt.decode(&token)?;

    // TODO: Implement blacklist checking
    // check if access token is on blacklist
    // if it is, error out

    Ok(decoded.claims)
}

#[post("login/password")]
pub(crate) async fn login() -> impl Responder {
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

#[post("logout")]
pub(crate) async fn logout(state: State, req: HttpRequest) -> AppResult<String> {
    let jwt = state.jwt.clone();
    let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout
    // check if Authentication header has bearer token
    // if not, error out, because the user isn't logged in get current jwt
    // add jwt to blacklist
    // get current refresh token
    // add refresh token to blacklist

    Ok(sub)
}

#[post("logout/all")]
pub(crate) async fn logout_all(state: State, req: HttpRequest) -> AppResult<String> {
    let jwt = state.jwt.clone();
    let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout for all
    // get all jwt for current user
    // add jwts to blacklist
    // get all refresh tokens for current user
    // add refresh tokens to blacklist

    Ok(sub)
}

#[post("signup")]
pub(crate) async fn signup(state: State, req: HttpRequest) -> AppResult<String> {
    let jwt = state.jwt.clone();
    if !claims(&req, jwt).await.is_err() {
        return Err(AppError::SignupError(SignupError::AlreadyLoggedIn));
    };

    // TODO: implement signup

    Ok("Implement signup here".to_string())
}

#[post("refresh")]
pub(crate) async fn refresh() -> impl Responder {
    // TODO: Add refresh token logic
    // check if Authentication header has bearer token
    // if not, error out
    // check if access token is on blacklist
    // if it is, error out
    // check if refresh token is on blacklist
    // if it is, error out

    "refresh not implemented"
}

#[get("me")]
pub(crate) async fn me(state: State, req: HttpRequest) -> Result<String, AppError> {
    let jwt = state.jwt.clone();
    let claims = claims(&req, jwt).await?;

    // TODO: Add user info logic
    // get user info
    // sanitize it
    // return it

    Ok(claims.sub)
}

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path)
        .service(login)
        .service(logout)
        .service(signup)
        .service(refresh)
        .service(me)
}
