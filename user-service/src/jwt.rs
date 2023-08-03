use derive_more::{Display, Error};
use jsonwebtoken::{
    errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct JwtService {
    decode_key: DecodingKey,
    encode_key: EncodingKey,
    validation: Validation,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Claims {
    pub(crate) exp: i64,
    pub(crate) sub: String,
    pub(crate) iat: i64,
    pub(crate) iss: String,
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
    pub(crate) fn new(issuer: &str, jwt_private_key: Vec<u8>, jwt_public_key: Vec<u8>) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);

        JwtService {
            decode_key: DecodingKey::from_rsa_pem(jwt_public_key.as_slice())
                .expect("could not load public key"),
            encode_key: EncodingKey::from_rsa_pem(jwt_private_key.as_slice())
                .expect("could not load private key"),
            validation,
        }
    }

    pub fn decode(self, token: &str) -> Result<TokenData<Claims>, JwtServiceError> {
        let decoded = jsonwebtoken::decode::<Claims>(&token, &self.decode_key, &self.validation)?;

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
    use std::fs;

    use jsonwebtoken::TokenData;

    use crate::jwt::JwtServiceError;

    use super::{Claims, JwtService};

    static ISSUER: &'static str = "user-service";
    static SUB: &'static str = "IAMUSER";

    fn fixture() -> JwtService {
        let jwt_private_key = fs::read("./private.pem").unwrap();
        let jwt_public_key = fs::read("./public.pem").unwrap();

        JwtService::new(ISSUER, jwt_private_key, jwt_public_key)
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
            sub: SUB.to_owned(),
        };

        let result = service.encode(claims).unwrap();
        let should_be_jwt = include_str!("./fixtures/jwt/test_correct_jwt.txt").trim_end();

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
            sub: SUB.to_owned(),
        };

        let token = service.clone().encode(claims).unwrap();
        let TokenData { claims, .. } = service.decode(&token).unwrap();

        let now = time::OffsetDateTime::now_utc();
        let duration = time::Duration::new(60 * 15, 0);
        let test_against_claims = Claims {
            iat: now.unix_timestamp(),
            iss: ISSUER.to_owned(),
            exp: (now + duration).unix_timestamp(),
            sub: SUB.to_owned(),
        };

        assert_eq!(claims, test_against_claims)
    }

    #[test]
    fn decode_invalid_token() {
        let service = fixture();

        let token = "BADTOKEN";
        assert!(match service.decode(token) {
            Err(JwtServiceError::JsonWebTokenError(e)) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => true,
                _ => false,
            },
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
            sub: SUB.to_owned(),
        };

        let token = service.clone().encode(claims).unwrap();

        assert!(match service.decode(&token) {
            Err(JwtServiceError::JsonWebTokenError(e)) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => true,
                _ => false,
            },
            _ => false,
        });
    }

    #[test]
    fn decode_bad_issuer() {
        let service = fixture();
        let token = include_str!("./fixtures/jwt/test_bad_issuer.txt").trim_end();

        assert!(match service.decode(token) {
            Err(JwtServiceError::JsonWebTokenError(e)) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => true,
                _ => false,
            },
            _ => false,
        });
    }

    #[test]
    fn decode_bad_algorithm() {
        let service = fixture();
        let token = include_str!("./fixtures/jwt/test_bad_algorithm.txt").trim_end();

        assert!(match service.decode(token) {
            Err(JwtServiceError::JsonWebTokenError(e)) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => true,
                _ => false,
            },
            _ => false,
        });
    }
}
