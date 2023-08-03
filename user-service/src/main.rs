pub(crate) mod error;
pub(crate) mod health;
pub(crate) mod jwt;
pub(crate) mod v1;

use actix_web::{get, web::Data, App, HttpServer, Responder};

use dotenvy::dotenv;
use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
};
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
pub(crate) struct Config {
    database_url: String,
    private_key_path: String,
    public_key_path: String,
    port: u16,
    ip: IpAddr,
}

impl Config {
    fn figment() -> Figment {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("USER_"))
            .merge(Env::raw().only(&["DATABASE_URL"]))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database_url: "".to_owned(),
            private_key_path: "./private.pem".to_owned(),
            public_key_path: "./public.pem".to_owned(),
            port: 8999,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv();
    tracing_subscriber::fmt::init();

    let config: Config = Config::figment()
        .extract()?;

    let jwt_private_key = fs::read(config.private_key_path)?;
    let jwt_public_key = fs::read(config.public_key_path)?;
    let jwt = JwtService::new(jwt_private_key, jwt_public_key);

    info!(
        address = config.ip.to_string(),
        port = config.port,
        "Initializing server"
    );

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { jwt: jwt.clone() }))
            .wrap(TracingLogger::default())
            .service(ping)
            .service(health::router("health"))
            .service(v1::router("api/v1"))
    })
    .bind((config.ip, config.port))?
    .run()
    .await
    .map_err(anyhow::Error::from)
}
