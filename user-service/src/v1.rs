use actix_web::{get, post, web, Responder, Scope};

#[allow(dead_code)]
pub(crate) async fn is_logged_in() -> bool {
    false
}

#[post("login/password")]
pub(crate) async fn login() -> impl Responder {
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
pub(crate) async fn logout() -> impl Responder {
    // check if Authentication header has bearer token
    // if not, error out, because the user isn't logged in
    // get current jwt
    // add jwt to blacklist
    // get current refresh token
    // add refresh token to blacklist
    "logout not implemented"
}

#[post("logout/all")]
pub(crate) async fn logout_all() -> impl Responder {
    // check if Authentication header has bearer token
    // if not, error out, because the user isn't logged in
    // get current jwt
    // get all jwt for current user
    // add jwts to blacklist
    // get all refresh tokens for current user
    // add refresh tokens to blacklist

    "logout all not implemented"
}

#[post("signup")]
pub(crate) async fn signup() -> impl Responder {
    // check if Authentication header has bearer token
    // if yes, error out, because the user is logged in
    //
    "signup not implemented"
}

#[post("refresh")]
pub(crate) async fn refresh() -> impl Responder {
    // check if Authentication header has bearer token
    // if not, error out
    // check if access token is on blacklist
    // if it is, error out
    // check if refresh token is on blacklist
    // if it is, error out
    //
    "refresh not implemented"
}

#[get("me")]
pub(crate) async fn me() -> impl Responder {
    // check if Authentication header has bearer token
    // if not, error out
    // check if access token is on blacklist
    // if it is, error out
    // get user info for access token's ID
    // sanitize it
    // return it

    "me not implemented"
}

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path)
        .service(login)
        .service(logout)
        .service(signup)
        .service(refresh)
}
