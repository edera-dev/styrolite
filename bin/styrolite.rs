use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use env_logger::{Env, fmt::TimestampPrecision};
use styrolite::config::{Config, Wrappable};

fn main() -> Result<()> {
    let Some(config_path) = env::args().nth(1) else {
        bail!("missing config file path (usage: styrolite <config.json>)");
    };
    let config_path = PathBuf::from(config_path);

    if !config_path.exists() {
        bail!("config file '{}' does not exist", config_path.display());
    }

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp(Some(TimestampPrecision::Micros))
        .init();

    let raw = fs::read(&config_path)
        .with_context(|| format!("failed to read config file '{}'", config_path.display()))?;
    let config: Config = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse config file '{}'", config_path.display()))?;
    match config {
        Config::Create(create) => create.wrap(),
        Config::Attach(attach) => attach.wrap(),
    }
}
