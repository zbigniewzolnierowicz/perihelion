use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct AppErrorResponse {
    pub(crate) message: String,
    pub(crate) timestamp: time::OffsetDateTime,
}
