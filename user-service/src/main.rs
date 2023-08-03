pub(crate) mod error;
pub(crate) mod health;
pub(crate) mod jwt;
pub(crate) mod v1;

use actix_web::{get, web::Data, App, HttpServer, Responder};

use env_logger::Env;
use std::fs;
use tracing::info;
use tracing_actix_web::TracingLogger;

use crate::jwt::JwtService;

pub(crate) const PONG: &str = "pong!";

#[get("/ping")]
async fn ping() -> impl Responder {
    PONG
}

pub(crate) struct AppState {
    pub(crate) jwt: JwtService,
}

pub(crate) type State = Data<AppState>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    // TODO: replace with central config
    let jwt_private_key = fs::read("private.pem")?;
    let jwt_public_key = fs::read("public.pem")?;
    let jwt = JwtService::new(jwt_private_key, jwt_public_key);

    info!(target: "initialization", "Initializing the server");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { jwt: jwt.clone() }))
            .wrap(TracingLogger::default())
            .service(ping)
            .service(health::health_check)
            .service(v1::router("api/v1"))
    })
    // TODO: replace with a central config for port
    .bind(("0.0.0.0", 8999))?
    .run()
    .await
}
