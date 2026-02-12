use std::{env, fs, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};
use clap::{Parser};
use env_logger::Env;
use styrolite::runner::CreateRequestBuilder;

#[derive(Clone, Debug)]
struct ResourceLimit {
    key: String,
    value: String,
}

#[derive(Clone, Debug)]
struct MountSpec {
    hostpath: String,
    jailpath: String,
    read_write: bool,
}

#[derive(Debug, Parser)]
#[command(
    name = "styrojail",
    about = "convenient jail-style styrolite frontend",
    version,
)]
struct Cli {
    #[arg(long)]
    no_default_mounts: bool,

    #[arg(long, value_name = "HOSTPATH:JAILPATH", value_parser = parse_mount)]
    mount: Vec<MountSpec>,

    #[arg(long, value_name = "key:value", value_parser = parse_resource_limit)]
    limit: Vec<ResourceLimit>,

    #[arg(value_name = "PROGRAM")]
    program: String,

    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

fn parse_mount(s: &str) -> Result<MountSpec> {
    let mut parts = s.split(':');

    let hostpath = parts
        .next()
        .ok_or(anyhow!("mount must look like /hostpath:/jailpath[:rw]"))?;

    let jailpath = parts
        .next()
        .ok_or(anyhow!("mount must look like /hostpath:/jailpath[:rw]"))?;

    let mode = parts.next();

    if parts.next().is_some() {
        return Err(anyhow!("mount must look like /hostpath:/jailpath[:rw]"));
    }

    if hostpath.is_empty() || jailpath.is_empty() {
        return Err(anyhow!("mount must look like /hostpath:/jailpath[:rw]"));
    }

    let read_write = match mode {
        None => false, // default = read-only
        Some("rw") => true,
        Some(_) => {
            return Err(anyhow!("only ':rw' is supported as a mount modifier"));
        }
    };

    Ok(MountSpec {
        hostpath: hostpath.to_string(),
        jailpath: jailpath.to_string(),
        read_write,
    })
}

fn parse_resource_limit(s: &str) -> Result<ResourceLimit> {
    let (k, v) = s
        .split_once('=')
        .ok_or(anyhow!("limit must look like key=value"))?;

    if k.is_empty() {
        return Err(anyhow!("limit key cannot be empty"));
    }

    Ok(ResourceLimit {
        key: k.to_string(),
        value: v.to_string(),
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let createreq = CreateRequestBuilder::new();

    let mut argv = Vec::with_capacity(1 + cli.args.len());
    argv.push(cli.program.clone());
    argv.extend(cli.args.iter().cloned());

    eprintln!("no_default_mount = {}", cli.no_default_mounts);
    eprintln!("mounts = {:?}", cli.mount);
    eprintln!("limits = {:?}", cli.limit);
    eprintln!("exec argv = {:?}", argv);
    
    Ok(())
}
