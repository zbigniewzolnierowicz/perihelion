use actix_web::{post, HttpRequest, Responder};

use crate::State;

#[post("logout")]
pub(crate) async fn logout_route(_state: State, _req: HttpRequest) -> impl Responder {
    // let jwt = state.jwt.clone();
    // let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout
    // check if Authentication header has bearer token
    // if not, error out, because the user isn't logged in get current jwt
    // add jwt to blacklist
    // get current refresh token
    // add refresh token to blacklist

    "implement logout"
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

