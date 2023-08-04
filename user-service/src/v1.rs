use actix_web::{
    get,
    http::header::{ToStrError, AUTHORIZATION},
    http::StatusCode,
    post, web, HttpRequest, HttpResponse, Responder, Scope,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use validator::Validate;

use crate::{
    dto::user::CreateUserPasswordDTO,
    error::{AppError, AppResult},
    jwt::{Claims, JwtService, JwtServiceError},
    models::user::User,
    State,
};

use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub(crate) enum LoginError {
    #[display(fmt = "Authorization header is missing!")]
    NoAuthHeader,
    AuthHeaderDecodeError(ToStrError),
    JwtServiceError(JwtServiceError),
}

impl From<ToStrError> for LoginError {
    fn from(value: ToStrError) -> Self {
        Self::AuthHeaderDecodeError(value)
    }
}

impl From<JwtServiceError> for LoginError {
    fn from(value: JwtServiceError) -> Self {
        Self::JwtServiceError(value)
    }
}

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

pub(crate) async fn claims(req: &HttpRequest, jwt: JwtService) -> Result<Claims, LoginError> {
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(LoginError::NoAuthHeader)?
        .to_str()?
        .to_string();

    // check if access token is valid
    // if not, error out

    let decoded = jwt.decode(&token)?;

    // TODO: Implement blacklist checking
    // check if access token is on blacklist
    // if it is, error out

    Ok(decoded.claims)
}

#[post("login/password")]
pub(crate) async fn login() -> impl Responder {
    // TODO: Implement login
    // check if Authentication header has bearer token
    // if yes, error out, because the user isn't logged in
    // get body
    // check if user exists
    // if doesn't exist, error out
    // generate access token JWT
    // store access token in database
    // generate refresh token
    // store refresh token in database
    // store refresh token in HttpOnly, Secure cookie
    // return access and refresh tokens

    "login not implemented"
}

#[post("logout")]
pub(crate) async fn logout(_state: State, _req: HttpRequest) -> AppResult<String> {
    // let jwt = state.jwt.clone();
    // let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout
    // check if Authentication header has bearer token
    // if not, error out, because the user isn't logged in get current jwt
    // add jwt to blacklist
    // get current refresh token
    // add refresh token to blacklist

    todo!("implement logout")
}

#[post("logout/all")]
pub(crate) async fn logout_all(_state: State, _req: HttpRequest) -> AppResult<String> {
    // let jwt = state.jwt.clone();
    // let Claims { sub, .. } = claims(&req, jwt).await?;

    // TODO: implement logout for all
    // get all jwt for current user
    // add jwts to blacklist
    // get all refresh tokens for current user
    // add refresh tokens to blacklist

    todo!("implement logout all devices")
}

#[post("signup")]
pub(crate) async fn signup(
    body: web::Json<CreateUserPasswordDTO>,
    state: State,
    req: HttpRequest,
) -> AppResult<impl Responder> {
    let jwt = state.jwt.clone();
    let db = state.db.clone();

    if claims(&req, jwt).await.is_ok() {
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

#[post("refresh")]
pub(crate) async fn refresh() -> impl Responder {
    // TODO: Add refresh token logic
    // check if Authentication header has bearer token
    // if not, error out
    // check if access token is on blacklist
    // if it is, error out
    // check if refresh token is on blacklist
    // if it is, error out

    "refresh not implemented"
}

#[get("me")]
pub(crate) async fn me(state: State, req: HttpRequest) -> Result<web::Json<User>, AppError> {
    let jwt = state.jwt.clone();
    let claims = claims(&req, jwt).await?;
    let db = state.db.clone();

    let result = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE users.id = $1"#,
        claims.sub
    )
    .fetch_one(&db)
    .await
    .map_err(SignupError::from)?;

    // TODO: sanitize output

    Ok(web::Json(result))
}

pub(crate) fn router(path: &str) -> Scope {
    web::scope(path)
        .service(login)
        .service(logout)
        .service(signup)
        .service(refresh)
        .service(me)
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
}
