use crate::config::Config;

pub(crate) fn get_config() -> Config {
    Config {
        private_key_path: "test/private.pem".into(),
        public_key_path: "test/public.pem".into(),
        ..Default::default()
    }
}
