use anyhow::Result;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub fn init() {
    let level = if cfg!(debug_assertions) {
        Level::DEBUG
    } else {
        Level::INFO
    };
    init_logger(level, false).expect("Failed to initialize logger");
}

pub fn init_test() {
    let _ = init_logger(Level::DEBUG, true);
}

fn init_logger(level: Level, with_target: bool) -> Result<()> {
    let subscriber_builder = FmtSubscriber::builder()
        .compact()
        .with_target(with_target)
        .without_time();
    let subscriber = subscriber_builder.with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}
