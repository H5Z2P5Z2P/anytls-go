use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

static LOGGING_INIT: OnceLock<()> = OnceLock::new();

pub fn init_tracing(default_filter: &str) {
    LOGGING_INIT.get_or_init(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
    });
}
