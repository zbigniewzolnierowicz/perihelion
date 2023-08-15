use std::collections::HashMap;

use eyre::eyre;

use actix_web::{get, http::StatusCode, web, HttpResponse, Responder, Scope};
use serde::Serialize;
use sqlx::{Pool, Postgres};
use tracing::instrument;

use crate::AppState;

#[derive(Serialize)]
enum Health {
    Good,
    Bad,
}

impl From<Health> for String {
    fn from(value: Health) -> Self {
        match value {
            Health::Good => "healthy".to_owned(),
            Health::Bad => "unhealthy".to_owned(),
        }
    }
}

#[instrument]
async fn database_health_check(pool: &Pool<Postgres>) -> color_eyre::Result<()> {
    sqlx::query("SELECT 1").fetch_one(pool).await?;

    Ok(())
}

#[instrument]
async fn redis_health_check(redis: &redis::Client) -> color_eyre::Result<()> {
    let mut conn = redis.get_connection()?;
    let result: String = redis::cmd("PING").query(&mut conn)?;
    if result != "PONG" {
        return Err(eyre!("Could not connect to Redis"));
    };

    Ok(())
}

#[get("")]
pub(crate) async fn health_check(data: web::Data<AppState>) -> impl Responder {
    let mut healthchecks: HashMap<&str, bool> = HashMap::new();
    healthchecks.insert("database", database_health_check(&data.db).await.is_ok());
    healthchecks.insert("redis", redis_health_check(&data.redis).await.is_ok());

    let count_of_failed = healthchecks.iter().filter(|(_key, value)| **value).count();

    let healthchecks: HashMap<&str, Health> = healthchecks
        .iter()
        .map(|(key, value)| {
            if *value {
                (*key, Health::Good)
            } else {
                (*key, Health::Bad)
            }
        })
        .collect();

    let status = if count_of_failed > 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    HttpResponse::build(status).json(healthchecks)
}

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path).service(health_check)
}
