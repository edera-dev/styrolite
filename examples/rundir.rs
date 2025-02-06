use std::env;

use anyhow::Result;
use env_logger::Env;

use styrolite::config::IdMapping;
use styrolite::runner::{CreateRequestBuilder, Runner};

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("usage: rundir path-to-litewrap-bin path-to-rootfs");
        std::process::exit(1);
    }

    let uidmap = IdMapping {
        base_nsid: 0,
        base_hostid: 1000,
        remap_count: 1,
    };

    let gidmap = IdMapping {
        base_nsid: 0,
        base_hostid: 1000,
        remap_count: 1,
    };

    let create_req = CreateRequestBuilder::new()
        .set_rootfs(args[2].as_str())
        .set_executable("/bin/sh")
        .set_arguments(vec!["-i"])
        .set_working_directory("/")
        .push_resource_limit("memory.max", "256M")
        .push_uid_mapping(uidmap)
        .push_gid_mapping(gidmap)
        .push_environment("container", "styrolite")
        .push_environment(
            "PATH",
            "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
        .to_request();

    let runner = Runner::new(args[1].as_str());
    match runner.run(create_req) {
        Ok(exitcode) => std::process::exit(exitcode),
        Err(e) => Err(e),
    }
}
