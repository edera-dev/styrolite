use std::{env, fs, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};
use clap::{Parser};
use env_logger::Env;
use styrolite::config::{MountSpec as StyroMountSpec};
use styrolite::runner::{CreateRequestBuilder, Runner};
use styrolite::namespace::Namespace;

#[derive(Clone, Debug)]
struct ResourceLimit {
    key: String,
    value: String,
}

#[derive(Clone, Debug)]
struct CliMountSpec {
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
    /// Path to styrolite binary (default: resolved via PATH)
    #[arg(long, default_value = "styrolite")]
    styrolite_bin: String,

    /// Do not synthesize default mounts (e.g. $CWD:$CWD:rw)
    #[arg(long)]
    no_default_mounts: bool,

    /// Additional bind-mounts for the jail
    #[arg(long, value_name = "HOSTPATH:JAILPATH", value_parser = parse_mount)]
    mount: Vec<CliMountSpec>,

    /// Additional cgroup2 resource limits for the jail
    #[arg(long, value_name = "key:value", value_parser = parse_resource_limit)]
    limit: Vec<ResourceLimit>,

    /// The program being jailed
    #[arg(value_name = "PROGRAM")]
    program: String,

    /// Arguments to the program being jailed
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

fn build_mounts(cli: &Cli) -> Result<Vec<CliMountSpec>> {
    let mut mounts = Vec::new();

    if !cli.no_default_mounts {
        let cwd: PathBuf = env::current_dir()
            .map_err(|e| anyhow!("failed to get CWD: {e}"))?;

        let cwd_str = cwd
            .to_str()
            .ok_or(anyhow!("CWD is not valid UTF-8"))?
            .to_string();

        mounts.push(CliMountSpec {
            hostpath: cwd_str.clone(),
            jailpath: cwd_str,
            read_write: true,
        });
    }

    // Then append user-specified mounts
    mounts.extend(cli.mount.clone());

    Ok(mounts)
}

fn parse_mount(s: &str) -> Result<CliMountSpec> {
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

    Ok(CliMountSpec {
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

fn to_styrolite_mount(m: &CliMountSpec) -> StyroMountSpec {
    StyroMountSpec {
        source: Some(m.hostpath.clone()),
        target: m.jailpath.clone(),
        fstype: None,
        bind: true,
        recurse: false,
        unshare: false,
        safe: true,
        create_mountpoint: true,
        read_only: !m.read_write,
        ..Default::default()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut builder = CreateRequestBuilder::new()
        .set_rootfs("/")
        .set_rootfs_readonly(true)
        .set_skip_two_stage_userns(true)
        .set_executable(&cli.program)
        .push_namespace(Namespace::Uts)
        .push_namespace(Namespace::Time)
        .push_namespace(Namespace::Pid)
        .push_namespace(Namespace::User)
        .push_namespace(Namespace::Ipc)
        .push_namespace(Namespace::Mount);

    let args_ref: Vec<&str> = cli.args.iter().map(|s| s.as_str()).collect();
    builder = builder.set_arguments(args_ref);

    let mounts = build_mounts(&cli)?;

    for m in &mounts {
        builder = builder.push_mount(to_styrolite_mount(m));
    }

    for lim in &cli.limit {
        builder = builder.push_resource_limit(&lim.key, &lim.value);
    }

    let req = builder.to_request();
    let runner = Runner::new(&cli.styrolite_bin);
    runner.exec(req)?;

    Err(anyhow!("styrolite exec failed"))
}
