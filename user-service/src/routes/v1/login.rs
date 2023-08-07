use actix_web::{
    body::BoxBody, http::StatusCode, post, web, HttpRequest, HttpResponse, ResponseError,
};

use argon2::{PasswordHash, PasswordVerifier};
use derive_more::Display;

use crate::{
    dto::login::{LoginDTO, LoginResponse},
    jwt::{Claims, JwtServiceError},
    login_check::{get_logged_in_user_claims, LoginCheckError},
    models::user::{Credential, CredentialType, User},
    State,
};

#[derive(Debug, Display)]
pub(crate) enum LoginError {
    LoginCheckError(LoginCheckError),
    #[display(fmt = "User is already logged in.")]
    AlreadyLoggedIn,
    #[display(fmt = "User does not exist.")]
    UserDoesNotExist,
    #[display(fmt = "Incorrect password.")]
    BadPassword,
    Argon2HashError(argon2::password_hash::Error),
    DBError(sqlx::Error),
    JwtServiceError(JwtServiceError),
}

impl ResponseError for LoginError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::LoginCheckError(e) => e.status_code(),
            Self::AlreadyLoggedIn => StatusCode::FORBIDDEN,
            Self::UserDoesNotExist => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::LoginCheckError(e) => e.error_response(),
            Self::AlreadyLoggedIn => HttpResponse::build(self.status_code()).body(self.to_string()),
            Self::DBError(e) => HttpResponse::build(self.status_code()).body(e.to_string()),
            e => HttpResponse::build(self.status_code()).body(e.to_string()),
        }
    }
}

impl From<sqlx::Error> for LoginError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::RowNotFound => Self::UserDoesNotExist,
            _ => Self::DBError(value),
        }
    }
}

impl From<argon2::password_hash::Error> for LoginError {
    fn from(value: argon2::password_hash::Error) -> Self {
        Self::Argon2HashError(value)
    }
}

impl From<JwtServiceError> for LoginError {
    fn from(value: JwtServiceError) -> Self {
        Self::JwtServiceError(value)
    }
}

#[post("login/password")]
pub(crate) async fn login_route(
    body: web::Json<LoginDTO>,
    state: State,
    req: HttpRequest,
) -> Result<web::Json<LoginResponse>, LoginError> {
    // TODO: Implement login
    let jwt = state.jwt.clone();
    let db = state.db.clone();
    let config = state.config.clone();
    let argon = argon2::Argon2::default();

    if get_logged_in_user_claims(&req, jwt.clone()).await.is_ok() {
        return Err(LoginError::AlreadyLoggedIn);
    };

    // check if user exists

    let LoginDTO { username, password } = body.into_inner();
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE username = $1", username)
        .fetch_one(&db)
        .await
        .map_err(LoginError::from)?;

    let Credential {
        credential_content, ..
    } = sqlx::query_as!(
        Credential,
        r#"SELECT
        credential_type as "credential_type: CredentialType",
        user_id,
        credential_content
        FROM credentials
        WHERE user_id = $1 AND credential_type = 'password'"#,
        user.id
    )
    .fetch_one(&db)
    .await
    .map_err(LoginError::from)?;

    let hash = PasswordHash::new(&credential_content).map_err(LoginError::from)?;

    if argon.verify_password(password.as_bytes(), &hash).is_err() {
        return Err(LoginError::BadPassword);
    };

    // generate access token JWT

    let (claims_at, expiration_at) = Claims::new_access_token(&config, user.clone());
    let access_token = jwt.clone().encode(claims_at).map_err(LoginError::from)?;

    // generate refresh token
    let (claims_rt, expiration_rt) = Claims::new_refresh_token(&config, user.clone());
    let refresh_token = jwt.encode(claims_rt).map_err(LoginError::from)?;

    let mut tx = db.begin().await.map_err(LoginError::from)?;

    // store access token in database
    sqlx::query!(
        "INSERT INTO jwt (user_id, content, expiration) VALUES ($1, $2, $3)",
        &user.id,
        access_token,
        expiration_at
    )
    .execute(&mut *tx)
    .await
    .map_err(LoginError::from)?;

    // store refresh token in database
    sqlx::query!(
        "INSERT INTO refresh (user_id, content, expiration) VALUES ($1, $2, $3)",
        &user.id,
        refresh_token,
        expiration_rt
    )
    .execute(&mut *tx)
    .await
    .map_err(LoginError::from)?;

    // store refresh token in HttpOnly, Secure cookie

    tx.commit().await.map_err(LoginError::from)?;
    // return access and refresh tokens

    Ok(web::Json(LoginResponse {
        access_token: access_token.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use actix_web::http::StatusCode;
    use actix_web::test;
    use reqwest::header::SET_COOKIE;
    use sqlx::PgPool;

    use super::LoginResponse;
    use crate::{create_app, test_utils::get_config};

    #[sqlx::test(fixtures("users"))]
    async fn login_correct(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "jimmyjimmyjimmy",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/login/password")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;
        let status = result.status();
        let headers = result.headers().clone();
        let body: LoginResponse = test::try_read_body_json(result)
            .await
            .expect("Could not read body");

        assert_eq!(status, StatusCode::OK);
        assert!(!body.access_token.is_empty());
        assert_eq!(headers.get(SET_COOKIE).unwrap(), "ERERE");
    }

    fn login_already_logged_in() {}
    fn login_missing_username() {}
    fn login_missing_password() {}
    fn login_user_does_not_exist() {}
    fn login_wrong_password() {}
}
