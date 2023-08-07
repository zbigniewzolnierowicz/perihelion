use actix_web::{post, Responder};

#[post("refresh")]
pub(crate) async fn refresh_route() -> impl Responder {
    // TODO: Add refresh token logic
    // check if refresh token is on blacklist
    // if it is, error out
    // otherwise, issue new access token and refresh token
    // add previous refresh token to blacklist

    "refresh not implemented"
}
