use derive_more::{Display, Error};
use jsonwebtoken::{
    errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{config::Config, models::user::User};

#[derive(Clone)]
pub(crate) struct JwtService {
    decode_key: DecodingKey,
    encode_key: EncodingKey,
    validation: Validation,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Claims {
    pub(crate) exp: i64,
    pub(crate) sub: Uuid,
    pub(crate) iat: i64,
    pub(crate) iss: String,
    pub(crate) token_type: TokenType,
}

#[derive(Serialize, Deserialize, EnumString, PartialEq, Debug)]
pub(crate) enum TokenType {
    AccessToken,
    RefreshToken,
}

impl Claims {
    pub(crate) fn new(
        duration: Duration,
        issuer: &str,
        subject: User,
        token_type: TokenType,
    ) -> (Self, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        let exp = now + duration;
        (
            Self {
                exp: (now + duration).unix_timestamp(),
                sub: subject.id,
                iat: now.unix_timestamp(),
                iss: issuer.to_owned(),
                token_type,
            },
            exp,
        )
    }

    pub(crate) fn new_access_token(config: &Config, subject: User) -> (Self, OffsetDateTime) {
        let duration = Duration::new(config.access_token_expiration, 0);

        Self::new(duration, &config.hostname, subject, TokenType::AccessToken)
    }

    pub(crate) fn new_refresh_token(config: &Config, subject: User) -> (Self, OffsetDateTime) {
        let duration = Duration::new(config.refresh_token_expiration, 0);

        Self::new(duration, &config.hostname, subject, TokenType::AccessToken)
    }
}

#[derive(Debug, Display, Error)]
pub(crate) enum JwtServiceError {
    JsonWebTokenError(JwtError),
}

impl From<JwtError> for JwtServiceError {
    fn from(value: JwtError) -> Self {
        Self::JsonWebTokenError(value)
    }
}

impl JwtService {
    pub(crate) fn new(
        issuer: &str,
        jwt_private_key: Vec<u8>,
        jwt_public_key: Vec<u8>,
    ) -> Result<Self, JwtServiceError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);

        Ok(JwtService {
            decode_key: DecodingKey::from_rsa_pem(jwt_public_key.as_slice())
                .map_err(JwtServiceError::from)?,
            encode_key: EncodingKey::from_rsa_pem(jwt_private_key.as_slice())
                .map_err(JwtServiceError::from)?,
            validation,
        })
    }

    pub fn decode(self, token: &str) -> Result<TokenData<Claims>, JwtServiceError> {
        let decoded = jsonwebtoken::decode::<Claims>(token, &self.decode_key, &self.validation)?;

        Ok(decoded)
    }

    pub fn encode(self, claims: Claims) -> Result<String, JwtServiceError> {
        let decoded =
            jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encode_key)?;

        Ok(decoded)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use std::fs;

    use jsonwebtoken::{EncodingKey, TokenData};
    use uuid::Uuid;

    use crate::jwt::{JwtServiceError, TokenType};

    use super::{Claims, JwtService};

    static ISSUER: &str = "user-service";
    static SUB: Uuid = Uuid::nil();

    fn fixture() -> JwtService {
        let jwt_private_key = fs::read("./test/private.pem").unwrap();
        let jwt_public_key = fs::read("./test/public.pem").unwrap();

        JwtService::new(ISSUER, jwt_private_key, jwt_public_key).unwrap()
    }

    #[test]
    fn encode_properly() {
        let service = fixture();
        let now = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
        let duration = time::Duration::new(60 * 15, 0);
        let claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        let result = service.encode(claims).unwrap();
        let should_be_jwt = include_str!("fixtures/test_correct_jwt.txt").trim_end();

        assert_eq!(result, should_be_jwt);
    }

    #[test]
    fn decode_properly() {
        let service = fixture();

        let now = time::OffsetDateTime::now_utc();
        let duration = time::Duration::new(60 * 15, 0);
        let claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        let token = service.clone().encode(claims).unwrap();
        let TokenData { claims, .. } = service.decode(&token).unwrap();

        let now = time::OffsetDateTime::now_utc();
        let duration = time::Duration::new(60 * 15, 0);
        let test_against_claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        assert_eq!(claims, test_against_claims)
    }

    #[test]
    fn decode_invalid_token() {
        let service = fixture();

        let token = "BADTOKEN";
        assert!(match service.decode(token) {
            Err(JwtServiceError::JsonWebTokenError(e)) =>
                matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidToken),
            _ => false,
        });
    }

    #[test]
    fn decode_expired_token() {
        let service = fixture();
        let now = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
        let duration = time::Duration::new(60 * 15, 0);
        let claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        let token = service.clone().encode(claims).unwrap();

        assert!(match service.decode(&token) {
            Err(JwtServiceError::JsonWebTokenError(e)) =>
                matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature),
            _ => false,
        });
    }

    #[test]
    fn decode_bad_issuer() {
        let service = fixture();
        let now = time::OffsetDateTime::now_utc();
        let duration = time::Duration::new(60 * 15, 0);
        let claims = Claims {
            iat: now.unix_timestamp(),
            iss: "BADISSUERREALLYBADNOREALLY".to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        let token = service.clone().encode(claims).unwrap();

        assert!(match service.decode(&token) {
            Err(JwtServiceError::JsonWebTokenError(e)) =>
                matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidIssuer),
            _ => false,
        });
    }

    #[test]
    fn decode_bad_algorithm() {
        let now = time::OffsetDateTime::now_utc();
        let duration = time::Duration::new(60 * 15, 0);
        let claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB,
            token_type: TokenType::AccessToken,
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_base64_secret("UEFTU1dPUkQK").unwrap(),
        )
        .unwrap();

        let service = fixture();

        assert!(match service.decode(&token) {
            Err(JwtServiceError::JsonWebTokenError(e)) =>
                matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidAlgorithm),
            _ => false,
        });
    }
}
