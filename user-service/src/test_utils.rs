#![allow(clippy::unwrap_used)]

use crate::{config::Config, create_app};

pub(crate) fn get_config() -> Config {
    Config {
        private_key_path: "test/private.pem".into(),
        public_key_path: "test/public.pem".into(),
        ..Default::default()
    }
}

pub(crate) fn init_global_config() {
    Config::init_global(get_config());
}
use actix_web::{
    body::MessageBody,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    App, Error,
};
use sqlx::PgPool;

pub(crate) fn create_test_app(
    pool: PgPool,
) -> color_eyre::Result<
    App<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<impl MessageBody>,
            Error = Error,
            InitError = (),
        >,
    >,
> {
    init_global_config();
    let config = Config::global();

    let redis = redis::Client::open(config.redis_url.clone()).unwrap();
    create_app(pool, redis)
}
