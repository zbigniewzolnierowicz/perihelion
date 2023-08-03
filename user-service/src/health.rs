use std::collections::HashMap;

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

impl Into<String> for Health {
    fn into(self) -> String {
        match self {
            Self::Bad => "unhealthy".to_owned(),
            Self::Good => "healthy".to_owned(),
        }
    }
}

#[instrument]
async fn database_health_check(pool: &Pool<Postgres>) -> color_eyre::Result<()> {
    sqlx::query("SELECT 1").fetch_one(pool).await?;

    Ok(())
}

#[get("")]
pub(crate) async fn health_check(data: web::Data<AppState>) -> impl Responder {
    let mut healthchecks: HashMap<&str, bool> = HashMap::new();
    healthchecks.insert("database", database_health_check(&data.db).await.is_ok());

    let count_of_failed = healthchecks.iter().filter(|(_key, value)| **value).count();

    let healthchecks: Vec<(&str, Health)> = healthchecks.iter().map(|(key, value)| {
        if *value {
            (*key, Health::Good)
        } else {
            (*key, Health::Bad)
        }
    }).collect();


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
