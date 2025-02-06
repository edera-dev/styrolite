use std::{env, fs, path::PathBuf};

use anyhow::Result;
use styrolite::config::{Config, Wrappable};
use env_logger::Env;

fn main() -> Result<()> {
    let config_path = env::args().nth(1).expect("config file path missing");
    let config_path = PathBuf::from(config_path);

    if !config_path.exists() {
        panic!("config file did not exist");
    }

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config: Config = serde_json::from_slice(&fs::read(&config_path)?)?;
    match config {
        Config::Create(create) => create.wrap(),
        Config::Attach(attach) => attach.wrap(),
    }
}
