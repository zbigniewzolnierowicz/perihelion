use derive_more::{Display, Error};
use jsonwebtoken::{
    errors::Error as JwtError,
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct JwtService {
    decode_key: DecodingKey,
    encode_key: EncodingKey,
    validation: Validation,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) exp: usize,
    pub(crate) sub: String,
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
    pub(crate) fn new(jwt_private_key: Vec<u8>, jwt_public_key: Vec<u8>) -> Self {
        let validation = Validation::new(Algorithm::RS256);
        JwtService {
            decode_key: DecodingKey::from_rsa_pem(jwt_public_key.as_slice())
                .expect("could not load public key"),
            encode_key: EncodingKey::from_rsa_pem(jwt_private_key.as_slice())
                .expect("could not load private key"),
            validation,
        }
    }

    pub fn decode(self, token: String) -> Result<TokenData<Claims>, JwtServiceError> {
        let decoded = jsonwebtoken::decode::<Claims>(&token, &self.decode_key, &self.validation)?;

        Ok(decoded)
    }

    pub fn encode(self, claims: Claims) -> Result<String, JwtServiceError> {
        let decoded = jsonwebtoken::encode(&Header::default(), &claims, &self.encode_key)?;

        Ok(decoded)
    }
}

#[cfg(test)]
mod test {
    use lazy_static::lazy_static;
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        pkcs8::LineEnding,
        RsaPrivateKey, RsaPublicKey,
    };

    use super::JwtService;

    lazy_static! {
        static ref JWT_SERVICE: JwtService = fixture();
    }

    fn fixture() -> JwtService {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

        let priv_key_pem = priv_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("could not encode to PEM");

        let pub_key_pem = RsaPublicKey::from(&priv_key)
            .to_pkcs1_pem(LineEnding::LF)
            .expect("could not encode to PEM");

        JwtService::new(
            priv_key_pem.as_bytes().to_vec(),
            pub_key_pem.as_bytes().to_vec(),
        )
    }

    #[test]
    fn encode_properly() {
        let _service = JWT_SERVICE.clone();
        todo!("implement test for properly encoding")
    }

    #[test]
    fn encode_missing_required_claim() {
        let _service = JWT_SERVICE.clone();
        todo!("implement test for missing required claims")
    }

    #[test]
    fn decode_properly() {
        let _service = JWT_SERVICE.clone();
        todo!("implement test for decoding properly")
    }

    #[test]
    fn decode_invalid_token() {
        let _service = JWT_SERVICE.clone();
        todo!("implement test for erroring when bad token")
    }

    #[test]
    fn decode_expired_token() {
        let _service = JWT_SERVICE.clone();
        todo!("implement test for erroring when expired token")
    }
}
