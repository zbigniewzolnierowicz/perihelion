use std::collections::HashMap;

use actix_web::{get, http::StatusCode, HttpResponse, Responder};

use crate::PONG;

const HEALTHY: &str = "healthy";
const UNHEALTHY: &str = "unhealthy";

async fn service_health_check() -> &'static str {
    // TODO: replace with a central config for port
    let res = reqwest::get("http://localhost:8999/ping").await;
    match res {
        Ok(d) => d.text().await.map_or(UNHEALTHY, |t| {
            if t == PONG.to_string() {
                HEALTHY
            } else {
                UNHEALTHY
            }
        }),
        Err(_) => UNHEALTHY,
    }
}

#[get("/health")]
pub(crate) async fn health_check() -> impl Responder {
    let mut healthchecks = HashMap::new();
    healthchecks.insert("user-service", service_health_check().await);

    HttpResponse::build(StatusCode::OK).json(healthchecks)
}
