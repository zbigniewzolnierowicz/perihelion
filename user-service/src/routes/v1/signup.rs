use actix_web::{
    body::BoxBody, http::StatusCode, post, web, HttpRequest, HttpResponse, Responder, ResponseError,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use validator::Validate;

use crate::{dto::user::CreateUserPasswordDTO, error::AppErrorResponse, models::user::User, State, login_check::get_logged_in_user_claims};

use derive_more::Display;

#[derive(Debug, Display)]
pub(crate) enum SignupError {
    #[display(fmt = "User is already logged in.")]
    AlreadyLoggedIn,
    #[display(fmt = "User with this email address already exists")]
    AlreadyExists,
    ValidationError(validator::ValidationErrors),
    DBError(sqlx::Error),
    Argon2PasswordHashError(argon2::password_hash::Error),
}

impl From<sqlx::Error> for SignupError {
    fn from(value: sqlx::Error) -> Self {
        if let Some(e) = value.as_database_error() {
            if e.is_unique_violation() {
                SignupError::AlreadyExists
            } else {
                SignupError::DBError(value)
            }
        } else {
            SignupError::DBError(value)
        }
    }
}

impl From<validator::ValidationErrors> for SignupError {
    fn from(value: validator::ValidationErrors) -> Self {
        Self::ValidationError(value)
    }
}

impl From<argon2::password_hash::Error> for SignupError {
    fn from(value: argon2::password_hash::Error) -> Self {
        Self::Argon2PasswordHashError(value)
    }
}

impl ResponseError for SignupError {
    fn status_code(&self) -> StatusCode {
        match self {
            SignupError::AlreadyLoggedIn => StatusCode::FORBIDDEN,
            SignupError::AlreadyExists => StatusCode::CONFLICT,
            SignupError::ValidationError(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let message = self.to_string();
        let timestamp = time::OffsetDateTime::now_utc();

        HttpResponse::build(self.status_code()).json(AppErrorResponse { message, timestamp })
    }
}

#[post("signup")]
pub(crate) async fn signup_route(
    body: web::Json<CreateUserPasswordDTO>,
    state: State,
    req: HttpRequest,
) -> Result<impl Responder, SignupError> {
    let jwt = state.jwt.clone();
    let db = state.db.clone();

    if get_logged_in_user_claims(&req, jwt).await.is_ok() {
        return Err(SignupError::AlreadyLoggedIn.into());
    };

    body.validate().map_err(SignupError::from)?;

    let CreateUserPasswordDTO {
        username,
        email,
        password,
        display_name,
    } = body.into_inner();

    let display_name = display_name.unwrap_or_else(|| username.clone());
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(SignupError::from)?;

    let mut tx = db.begin().await.map_err(SignupError::from)?;

    let result = sqlx::query_as!(
        User,
        "INSERT INTO users (username, email, display_name) VALUES ($1, $2, $3) RETURNING *",
        username,
        email,
        display_name,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(SignupError::from)?;

    sqlx::query!(
        "INSERT INTO credentials (user_id, credential_type, credential_content) VALUES ($1, 'password', $2)",
        result.id,
        password_hash.to_string()
    )
        .execute(&mut *tx)
        .await
        .map_err(SignupError::from)?;

    tx.commit().await.map_err(SignupError::from)?;

    // TODO: Add email activation

    Ok(HttpResponse::build(StatusCode::CREATED).finish())
}

#[cfg(test)]
mod tests {
    use actix_web::{http::StatusCode, test};
    use sqlx::PgPool;

    use crate::{config::Config, create_app};

    fn get_config() -> Config {
        Config {
            private_key_path: "test/private.pem".into(),
            public_key_path: "test/public.pem".into(),
            ..Default::default()
        }
    }

    #[sqlx::test]
    async fn signup_correct(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = actix_web::test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "username",
            "email": "username@example.com",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/signup")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;
        assert_eq!(result.status(), StatusCode::CREATED);
    }

    #[sqlx::test(fixtures("already-exists-user"))]
    fn signup_user_already_exists_username(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = actix_web::test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "jimmyjimmyjimmy",
            "email": "thereisnowayialreadyexist@example.com",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/signup")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;
        assert_eq!(result.status(), StatusCode::CONFLICT);
    }

    #[sqlx::test(fixtures("already-exists-user"))]
    fn signup_user_already_exists_email(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = actix_web::test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "thereisnowayialreadyexist",
            "email": "jimmy@example.com",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/signup")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;
        assert_eq!(result.status(), StatusCode::CONFLICT);
    }

    #[sqlx::test]
    fn signup_user_invalid_email(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = actix_web::test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "thereisnowayialreadyexist",
            "email": "INVALIDEMAIL",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/signup")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test]
    fn signup_user_invalid_username(pool: PgPool) {
        let config = get_config();
        let app = create_app(pool, config).unwrap();
        let test_service = actix_web::test::init_service(app).await;

        let payload = serde_json::json!({
            "username": "x",
            "email": "example@example.com",
            "password": "password",
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/signup")
            .set_json(payload)
            .to_request();

        let result = test::call_service(&test_service, req).await;

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test]
    fn signup_user_already_logged_in(_pool: PgPool) {
        // TODO: implement test for already logged in user
        todo!("implement test for already logged in user")
    }
}
