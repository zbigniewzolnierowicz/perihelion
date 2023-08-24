use derive_more::Error;
use strum::Display;

use mockall::automock;
use redis::Commands;

use crate::{ACCESS_TOKEN_BLACKLIST_KEY, REFRESH_TOKEN_BLACKLIST_KEY};

pub(crate) struct RedisBlacklistService(redis::Client);

#[automock]
pub(crate) trait BlacklistService {
    fn add_token(
        &mut self,
        key: &'static str,
        token: String,
    ) -> Result<bool, BlacklistServiceError>;
    fn add_tokens(
        &mut self,
        key: &'static str,
        tokens: Vec<String>,
    ) -> Result<bool, BlacklistServiceError>;
    fn is_in_blacklist(
        &mut self,
        key: &'static str,
        token: String,
    ) -> Result<bool, BlacklistServiceError>;
    fn add_access_token(&mut self, token: String) -> Result<bool, BlacklistServiceError>;
    fn add_access_tokens(&mut self, tokens: Vec<String>) -> Result<bool, BlacklistServiceError>;
    fn is_access_token_in_blacklist(
        &mut self,
        token: String,
    ) -> Result<bool, BlacklistServiceError>;
    fn add_refresh_token(&mut self, token: String) -> Result<bool, BlacklistServiceError>;
    fn add_refresh_tokens(&mut self, tokens: Vec<String>) -> Result<bool, BlacklistServiceError>;
    fn is_refresh_token_in_blacklist(
        &mut self,
        token: String,
    ) -> Result<bool, BlacklistServiceError>;
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

impl BlacklistService for RedisBlacklistService {
    fn add_token(
        &mut self,
        key: &'static str,
        token: String,
    ) -> Result<bool, BlacklistServiceError> {
        let mut connection = self.0.get_connection()?;

        connection.sadd(key, token)?;

        Ok(true)
    }

    fn add_access_token(&mut self, token: String) -> Result<bool, BlacklistServiceError> {
        self.add_token(ACCESS_TOKEN_BLACKLIST_KEY, token)
    }

    fn is_in_blacklist(
        &mut self,
        key: &'static str,
        token: String,
    ) -> Result<bool, BlacklistServiceError> {
        let mut connection = self.0.get_connection()?;

        let result: bool = connection.sismember(key, token)?;

        Ok(result)
    }

    fn is_access_token_in_blacklist(
        &mut self,
        token: String,
    ) -> Result<bool, BlacklistServiceError> {
        self.is_in_blacklist(ACCESS_TOKEN_BLACKLIST_KEY, token)
    }

    fn add_tokens(
        &mut self,
        key: &'static str,
        tokens: Vec<String>,
    ) -> Result<bool, BlacklistServiceError> {
        let mut connection = self.0.get_connection()?;

        connection.sadd(key, tokens)?;

        Ok(true)
    }

    fn add_access_tokens(&mut self, tokens: Vec<String>) -> Result<bool, BlacklistServiceError> {
        self.add_tokens(ACCESS_TOKEN_BLACKLIST_KEY, tokens)
    }

    fn add_refresh_token(&mut self,token:String) -> Result<bool,BlacklistServiceError> {
        self.add_token(REFRESH_TOKEN_BLACKLIST_KEY, token)
    }
    
    fn add_refresh_tokens(&mut self,tokens:Vec<String>) -> Result<bool,BlacklistServiceError> {
        self.add_tokens(REFRESH_TOKEN_BLACKLIST_KEY, tokens)
    }

    fn is_refresh_token_in_blacklist(&mut self,token:String,) -> Result<bool,BlacklistServiceError> {
        self.is_in_blacklist(REFRESH_TOKEN_BLACKLIST_KEY, token)
    }
}

impl RedisBlacklistService {
    pub(crate) fn new(client: redis::Client) -> Self {
        Self(client)
    }
}
