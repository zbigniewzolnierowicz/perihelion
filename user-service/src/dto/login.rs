use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct LoginDTO {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LoginResponse {
    pub access_token: String,
}
