use std::collections::HashMap;

use actix_web::{get, http::StatusCode, web, HttpResponse, Responder, Scope};
use sqlx::{Pool, Postgres};
use tracing::instrument;

use crate::AppState;

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
async fn database_health_check(pool: &Pool<Postgres>) -> Health {
    match sqlx::query("SELECT 1").fetch_one(pool).await {
        Ok(_) => Health::Good,
        Err(_) => Health::Bad,
    }
}

#[get("")]
pub(crate) async fn health_check(data: web::Data<AppState>) -> impl Responder {
    let mut healthchecks: HashMap<&str, String> = HashMap::new();

    healthchecks.insert("database", database_health_check(&data.db).await.into());

    HttpResponse::build(StatusCode::OK).json(healthchecks)
}

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path).service(health_check)
}
