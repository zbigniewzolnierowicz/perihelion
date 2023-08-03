pub(crate) mod error;
pub(crate) mod health;
pub(crate) mod jwt;
pub(crate) mod v1;

use actix_web::{get, web::Data, App, HttpServer, Responder};

use env_logger::Env as LogEnv;
use figment::{providers::Env, Figment};
use serde::{Deserialize, Serialize};
use std::{fs, net::{IpAddr, Ipv4Addr}};
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

#[derive(Serialize, Deserialize)]
pub(crate) struct AppConfig<'a> {
    database_url: &'a str,
    private_key_path: &'a str,
    public_key_path: &'a str,
    port: u16,
    ip: IpAddr,
}

impl Default for AppConfig<'_> {
    fn default() -> Self {
        AppConfig {
            database_url: "",
            private_key_path: "./private.pem",
            public_key_path: "./public.pem",
            port: 8999,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config: AppConfig = Figment::new()
        .merge(Env::prefixed("USER_"))
        .merge(Env::raw().only(&["DATABASE_URL"]))
        .extract()
        .expect("Could not load config.");

    env_logger::init_from_env(LogEnv::default().default_filter_or("info"));

    let jwt_private_key = fs::read(config.private_key_path)?;
    let jwt_public_key = fs::read(config.public_key_path)?;
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
    .bind((config.ip, config.port))?
    .run()
    .await
}
