use figment::providers::{Env, Serialized};
use figment::Figment;
use std::net::{IpAddr, Ipv4Addr};

use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Config {
    pub(crate) name: String,
    pub(crate) database_url: String,
    pub(crate) private_key_path: RelativePathBuf,
    pub(crate) public_key_path: RelativePathBuf,
    pub(crate) port: u16,
    pub(crate) ip: IpAddr,
    pub(crate) hostname: String,
    pub(crate) telemetry: bool,
}

#[cfg(not(tarpaulin_include))]
impl Config {
    pub(crate) fn figment() -> Figment {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("USER_"))
            .merge(Env::raw().only(&["DATABASE_URL"]))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: "user-service".to_owned(),
            hostname: "user-service.perihelion.local".to_owned(),
            database_url: "".to_owned(),
            private_key_path: "./private.pem".into(),
            public_key_path: "./public.pem".into(),
            port: 8999,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            telemetry: true,
        }
    }
}
