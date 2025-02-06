use std::env;

use anyhow::Result;
use env_logger::Env;

use styrolite::runner::{AttachRequestBuilder, Runner};

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("usage: attach path-to-litewrap-bin target-pid");
        std::process::exit(1);
    }

    let attach_req = AttachRequestBuilder::new()
        .set_pid(args[2].parse::<i32>()?)
        .set_executable("/bin/sh")
        .set_arguments(vec!["-i"])
        .set_working_directory("/")
        .push_environment("container", "edera")
        .push_environment(
            "PATH",
            "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
        .to_request();

    let runner = Runner::new(args[1].as_str());
    match runner.run(attach_req) {
        Ok(exitcode) => std::process::exit(exitcode),
        Err(e) => Err(e),
    }
}
