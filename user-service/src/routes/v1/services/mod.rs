use strum::Display;
use tokio::sync::Mutex;
use derive_more::Error;

use async_trait::async_trait;
use mockall::automock;

use crate::ACCESS_TOKEN_BLACKLIST_KEY;

pub(crate) struct RedisBlacklistService(pub(crate) Mutex<Box<dyn redis::ConnectionLike + Send>>);

#[async_trait]
#[automock]
pub(crate) trait BlacklistService {
    async fn add_token(&mut self, key: &'static str, token: String) -> Result<bool, BlacklistServiceError>;
    async fn is_in_blacklist(&mut self, key: &'static str, token: String) -> Result<bool, BlacklistServiceError>;
    async fn add_access_token(&mut self, token: String) -> Result<bool, BlacklistServiceError>;
    async fn is_access_token_in_blacklist(&mut self, token: String) -> Result<bool, BlacklistServiceError>;
}

#[derive(Debug, Display, Error)]
pub(crate) enum BlacklistServiceError {
    RedisError(redis::RedisError),
}

impl From<redis::RedisError> for BlacklistServiceError {
    fn from(value: redis::RedisError) -> Self {
        Self::RedisError(value)
    }
}

#[async_trait]
impl BlacklistService for RedisBlacklistService {
    async fn add_token(&mut self, key: &'static str, token: String) -> Result<bool, BlacklistServiceError> {
        let mut binding = self.0.lock().await;
        let connection = binding.as_mut();

        let result: bool = redis::cmd("SADD")
            .arg(key)
            .arg(token)
            .query(connection)?;

        Ok(result)
    }

    async fn add_access_token(&mut self, token: String) -> Result<bool, BlacklistServiceError> {
        self.add_token(ACCESS_TOKEN_BLACKLIST_KEY, token).await
    }

    async fn is_in_blacklist(&mut self, key: &'static str, token: String) -> Result<bool, BlacklistServiceError> {
        let mut binding = self.0.lock().await;
        let connection = binding.as_mut();

        let result: bool = redis::cmd("SISMEMBER")
            .arg(key)
            .arg(token)
            .query(connection)?;

        Ok(result)
    }

    async fn is_access_token_in_blacklist(&mut self, token: String) -> Result<bool, BlacklistServiceError> {
        self.is_in_blacklist(ACCESS_TOKEN_BLACKLIST_KEY, token).await
    }
}

impl RedisBlacklistService {
    pub(crate) fn new(conn: impl redis::ConnectionLike + Send + 'static) -> Self {
        Self(Mutex::new(Box::new(conn)))
    }
}
