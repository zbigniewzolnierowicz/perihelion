use actix_web::{web, Scope};
use tokio::sync::Mutex;

use crate::jwt::JwtService;

use self::services::blacklist::BlacklistService;

mod login;
mod logout;
mod refresh;
pub(crate) mod services;
mod signup;
mod user_info;

pub(crate) struct UserServiceStateInternal {
    pub(crate) jwt: JwtService,
    pub(crate) blacklist_service: Mutex<Box<dyn BlacklistService>>,
}

pub(crate) type UserServiceState = web::Data<UserServiceStateInternal>;

pub(crate) fn router(
    path: &str,
    jwt: JwtService,
    blacklist_service: impl BlacklistService + 'static,
) -> Scope {
    web::scope(path)
        .app_data(web::Data::new(UserServiceStateInternal {
            jwt,
            blacklist_service: Mutex::new(Box::new(blacklist_service)),
        }))
        .service(login::login_route)
        .service(signup::signup_route)
        .service(logout::logout_route)
        .service(logout::logout_all_route)
        .service(refresh::refresh_route)
        .service(user_info::user_info_route)
}
