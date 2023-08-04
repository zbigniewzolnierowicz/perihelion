use actix_web::{
    body::BoxBody, get, http::StatusCode, web, HttpRequest, HttpResponse,
    ResponseError,
};

use crate::{error::AppErrorResponse, models::user::User, State, login_check::{LoginCheckError, get_logged_in_user_claims}};

use derive_more::{Display, Error};

#[derive(Display, Debug, Error)]
pub(crate) enum UserInfoError {
    DatabaseError(sqlx::Error),
    LoginError(LoginCheckError),
}

impl From<sqlx::Error> for UserInfoError {
    fn from(value: sqlx::Error) -> Self {
        Self::DatabaseError(value)
    }
}

impl From<LoginCheckError> for UserInfoError {
    fn from(value: LoginCheckError) -> Self {
        Self::LoginError(value)
    }
}

impl ResponseError for UserInfoError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::LoginError(e) => e.status_code(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let message = match self {
            Self::DatabaseError(e) => e.to_string(),
            Self::LoginError(e) => return e.error_response(),
        };

        let timestamp = time::OffsetDateTime::now_utc();

        HttpResponse::build(self.status_code()).json(AppErrorResponse { message, timestamp })
    }
}

#[get("me")]
pub(crate) async fn user_info_route(state: State, req: HttpRequest) -> Result<web::Json<User>, UserInfoError> {
    let jwt = state.jwt.clone();
    let claims = get_logged_in_user_claims(&req, jwt).await.map_err(UserInfoError::from)?;
    let db = state.db.clone();

    let result = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE users.id = $1"#,
        claims.sub
    )
    .fetch_one(&db)
    .await
    .map_err(UserInfoError::from)?;

    // TODO: sanitize output

    Ok(web::Json(result))
}
