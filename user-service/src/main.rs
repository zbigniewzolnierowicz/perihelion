use actix_web::{get, App, HttpServer, Responder};
use env_logger::Env;
use tracing::info;
use tracing_actix_web::TracingLogger;


mod v1;

#[get("/ping")]
async fn ping() -> impl Responder {
    "pong!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    info!(target: "initialization", "Initializing the server");

    HttpServer::new(|| {
        App::new()
            .wrap(TracingLogger::default())
            .service(ping)
            .service(v1::router("api/v1"))
    })
    .bind(("0.0.0.0", 8999))?
    .run()
    .await
}
