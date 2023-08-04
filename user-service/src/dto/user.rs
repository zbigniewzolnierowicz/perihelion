use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Validate, Debug)]
pub(crate) struct CreateUserPasswordDTO {
    #[validate(length(min = 6))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}
