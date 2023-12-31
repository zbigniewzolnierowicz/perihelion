#![allow(dead_code)]

pub(crate) mod config;
pub(crate) mod dto;
pub(crate) mod error;
pub(crate) mod health;
pub(crate) mod jwt;
pub(crate) mod login_check;
pub(crate) mod models;
pub(crate) mod routes;
pub(crate) mod test_utils;

use std::fs;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::Error;
use actix_web::{get, web::Data, App, HttpServer, Responder};

use dotenvy::dotenv;

use opentelemetry::global;
use opentelemetry::runtime::TokioCurrentThread;
use opentelemetry::sdk::propagation::TraceContextPropagator;
use redis::Client as RedisClient;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::info;
use tracing_actix_web::TracingLogger;

use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::Registry;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

use crate::config::Config;
use crate::jwt::JwtService;
use crate::routes::v1;
use crate::routes::v1::services::blacklist::RedisBlacklistService;

pub(crate) const PONG: &str = "pong!";
pub(crate) const ACCESS_TOKEN_BLACKLIST_KEY: &str = "access_token:blacklist";
pub(crate) const REFRESH_TOKEN_BLACKLIST_KEY: &str = "refresh_token:blacklist";
pub(crate) const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

#[get("/ping")]
async fn ping() -> impl Responder {
    PONG
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) jwt: JwtService,
    pub(crate) db: PgPool,
    pub(crate) redis: RedisClient,
}

pub(crate) type State = Data<AppState>;

fn init_telemetry(app_name: &str) -> color_eyre::Result<()> {
    // Start a new Jaeger trace pipeline.
    // Spans are exported in batch - recommended setup for a production application.
    global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name(app_name)
        .install_batch(TokioCurrentThread)?;

    // Filter based on level - trace, debug, info, warn, error
    // Tunable via `RUST_LOG` env variable
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info"));

    // Create a `tracing` layer using the Jaeger tracer
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Create a `tracing` layer to emit spans as structured logs to stdout
    let formatting_layer = BunyanFormattingLayer::new(app_name.into(), std::io::stdout);

    // Combined them all together in a `tracing` subscriber
    let subscriber = Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(JsonStorageLayer)
        .with(formatting_layer);

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

#[actix_web::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let _ = dotenv();

    let config: Config = Config::figment().extract()?;

    if config.telemetry {
        init_telemetry(&config.name)?;
    };

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    let redis = RedisClient::open(config.redis_url.clone())?;

    let Config { ip, port, .. } = config;

    config.init_global();

    #[allow(clippy::expect_used)]
    HttpServer::new(move || create_app(db.clone(), redis.clone()).expect("Creating an app failed"))
        .bind((ip, port))?
        .run()
        .await
        .map_err(color_eyre::Report::from)
}

pub(crate) fn create_app(
    db: PgPool,
    redis: RedisClient,
) -> color_eyre::Result<
    App<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<impl MessageBody>,
            Error = Error,
            InitError = (),
        >,
    >,
> {
    let config = Config::global();
    let jwt_private_key = fs::read(config.private_key_path.relative())?;
    let jwt_public_key = fs::read(config.public_key_path.relative())?;
    let jwt = JwtService::new(&config.hostname, jwt_private_key, jwt_public_key)?;

    info!(
        address = config.ip.to_string(),
        port = config.port,
        "Initializing server"
    );

    let state = AppState {
        jwt,
        db,
        redis: redis.clone(),
    };

    let data = Data::new(state.clone());

    Ok(App::new()
        .app_data(data.clone())
        .wrap(TracingLogger::default())
        .service(ping)
        .service(health::router("health"))
        .service(v1::router(
            "api/v1",
            state.jwt.clone(),
            RedisBlacklistService::new(redis),
        )))
}
