use actix_web::{web, Scope};

mod login;
mod logout;
mod refresh;
mod signup;
mod user_info;

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path)
        .service(login::login_route)
        .service(signup::signup_route)
        .service(logout::logout_route)
        .service(logout::logout_all_route)
        .service(refresh::refresh_route)
        .service(user_info::user_info_route)
}
