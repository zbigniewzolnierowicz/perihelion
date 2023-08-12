use figment::providers::{Env, Serialized};
use figment::Figment;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Config {
    pub(crate) name: String,
    pub(crate) database_url: String,
    pub(crate) private_key_path: RelativePathBuf,
    pub(crate) public_key_path: RelativePathBuf,
    pub(crate) port: u16,
    pub(crate) ip: IpAddr,
    pub(crate) hostname: String,
    pub(crate) telemetry: bool,
    pub(crate) access_token_expiration: i64,
    pub(crate) refresh_token_expiration: i64,
}

#[cfg(not(tarpaulin_include))]
impl Config {
    pub(crate) fn figment() -> Figment {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("USER_"))
            .merge(Env::raw().only(&["DATABASE_URL"]))
    }
}

static SECONDS_IN_MINUTE: i64 = 60i64;
static MINUTES_IN_HOUR: i64 = 60i64;
static HOURS_IN_DAY: i64 = 24i64;

impl Default for Config {
    fn default() -> Self {
        let access_token_expiration: i64 = SECONDS_IN_MINUTE * 15;
        let refresh_token_expiration: i64 = SECONDS_IN_MINUTE * MINUTES_IN_HOUR * HOURS_IN_DAY * 30;

        Config {
            name: "user-service".to_owned(),
            hostname: "user-service.perihelion.local".to_owned(),
            database_url: "".to_owned(),
            private_key_path: "./private.pem".into(),
            public_key_path: "./public.pem".into(),
            port: 8999,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            telemetry: true,
            access_token_expiration,
            refresh_token_expiration,
        }
    }
}

static CONFIG_CELL: OnceLock<Config> = OnceLock::new();

impl Config {
    pub(crate) fn init_global(self) {
        let _ = CONFIG_CELL.set(self);
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn global() -> &'static Self {
        CONFIG_CELL
            .get()
            .expect("Config is not loaded yet somehow.")
    }
}
