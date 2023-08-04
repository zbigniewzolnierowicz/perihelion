use derive_more::Display;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(sqlx::Type, Debug, Display)]
#[sqlx(rename_all = "lowercase", type_name = "credential_type")]
pub(crate) enum CredentialType {
    Password,
}

#[derive(sqlx::FromRow, Debug)]
pub(crate) struct Credential {
    pub user_id: Uuid,
    pub credential_type: CredentialType,
    pub credential_content: String,
}

#[derive(sqlx::FromRow, Serialize)]
pub(crate) struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Jwt {
    #[sqlx(rename = "jwt_id")]
    pub id: Uuid,
    pub user_id: Uuid,
    pub content: String,
    pub expiration: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Refresh {
    #[sqlx(rename = "refresh_id")]
    pub id: Uuid,
    pub user_id: Uuid,
    pub content: String,
    pub expiration: OffsetDateTime,
}
