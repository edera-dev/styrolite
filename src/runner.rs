use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Result, anyhow};
use libc::{gid_t, pid_t, uid_t};
use mktemp::TempFile;

use crate::config::{
    AttachRequest, Capabilities, Configurable, CreateRequest, IdMapping, MountSpec, Mutation,
    ProcessResourceLimits,
};
use crate::namespace::Namespace;

fn add_to_cap_list(
    value: String,
    caps: &mut Option<Capabilities>,
    get_list: impl FnOnce(&mut Capabilities) -> &mut Option<Vec<String>>,
) {
    if caps.is_none() {
        *caps = Some(Capabilities::default());
    }

    if let Some(caps) = caps {
        let list = get_list(caps);
        if list.is_none() {
            *list = Some(Vec::new());
        }

        if let Some(list) = list {
            list.push(value);
        }
    }
}

#[derive(Default, Debug)]
pub struct AttachRequestBuilder {
    config: AttachRequest,
}

impl AttachRequestBuilder {
    pub fn new() -> AttachRequestBuilder {
        AttachRequestBuilder::default()
    }

    pub fn set_pid(mut self, pid: pid_t) -> AttachRequestBuilder {
        self.config.pid = pid;
        self
    }

    pub fn set_executable(mut self, executable: &str) -> AttachRequestBuilder {
        self.config.exec.executable = executable.to_string().into();
        self
    }

    pub fn set_arguments(mut self, args: Vec<&str>) -> AttachRequestBuilder {
        let converted_args: Vec<String> = args.into_iter().map(|arg| arg.to_string()).collect();
        self.config.exec.arguments = converted_args.into();
        self
    }

    pub fn set_working_directory(mut self, wd: &str) -> AttachRequestBuilder {
        self.config.exec.working_directory = wd.to_string().into();
        self
    }

    pub fn set_workload_id(mut self, workload_id: &str) -> AttachRequestBuilder {
        self.config.workload_id = workload_id.to_string().into();
        self
    }

    pub fn set_uid(mut self, uid: uid_t) -> AttachRequestBuilder {
        self.config.exec.uid = uid.into();
        self
    }

    pub fn set_gid(mut self, gid: gid_t) -> AttachRequestBuilder {
        self.config.exec.gid = gid.into();
        self
    }

    pub fn set_no_new_privs(mut self, no_new_privs: bool) -> AttachRequestBuilder {
        self.config.exec.no_new_privs = no_new_privs;
        self
    }

    pub fn push_environment(mut self, key: &str, value: &str) -> AttachRequestBuilder {
        if self.config.exec.environment.is_none() {
            self.config.exec.environment = BTreeMap::new().into();
        }

        if let Some(ref mut map) = self.config.exec.environment {
            map.insert(key.to_string(), value.to_string());
        }

        self
    }

    pub fn push_namespace(mut self, ns: Namespace) -> AttachRequestBuilder {
        if self.config.namespaces.is_none() {
            self.config.namespaces = vec![].into();
        }

        if let Some(ref mut nsset) = self.config.namespaces {
            nsset.push(ns);
        }

        self
    }

    pub fn push_raise_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.raise,
        );
        self
    }

    pub fn push_raise_ambient_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.raise_ambient,
        );
        self
    }

    pub fn push_drop_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.drop,
        );
        self
    }

    pub fn to_request(self) -> AttachRequest {
        self.config
    }
}

#[derive(Default, Debug)]
pub struct CreateRequestBuilder {
    /// The configuration object being constructed.
    config: CreateRequest,
}

impl CreateRequestBuilder {
    pub fn new() -> CreateRequestBuilder {
        CreateRequestBuilder::default()
    }

    pub fn set_rootfs(mut self, rootfs: &str) -> CreateRequestBuilder {
        self.config.rootfs = rootfs.to_string().into();
        self
    }

    pub fn set_rootfs_readonly(mut self, rootfs_readonly: bool) -> CreateRequestBuilder {
        self.config.rootfs_readonly = Some(rootfs_readonly);
        self
    }

    pub fn set_skip_two_stage_userns(
        mut self,
        skip_two_stage_userns: bool,
    ) -> CreateRequestBuilder {
        self.config.skip_two_stage_userns = Some(skip_two_stage_userns);
        self
    }

    pub fn set_executable(mut self, executable: &str) -> CreateRequestBuilder {
        self.config.exec.executable = executable.to_string().into();
        self
    }

    pub fn set_arguments(mut self, args: Vec<&str>) -> CreateRequestBuilder {
        let converted_args: Vec<String> = args.into_iter().map(|arg| arg.to_string()).collect();
        self.config.exec.arguments = converted_args.into();
        self
    }

    pub fn set_working_directory(mut self, wd: &str) -> CreateRequestBuilder {
        self.config.exec.working_directory = wd.to_string().into();
        self
    }

    pub fn set_workload_id(mut self, workload_id: &str) -> CreateRequestBuilder {
        self.config.workload_id = workload_id.to_string().into();
        self
    }

    pub fn set_uid(mut self, uid: uid_t) -> CreateRequestBuilder {
        self.config.exec.uid = uid.into();
        self
    }

    pub fn set_gid(mut self, gid: gid_t) -> CreateRequestBuilder {
        self.config.exec.gid = gid.into();
        self
    }

    pub fn set_no_new_privs(mut self, no_new_privs: bool) -> CreateRequestBuilder {
        self.config.exec.no_new_privs = no_new_privs;
        self
    }

    pub fn set_hostname(mut self, hostname: &str) -> CreateRequestBuilder {
        self.config.hostname = hostname.to_string().into();
        self
    }

    pub fn set_setgroups_deny(mut self, setgroups_deny: bool) -> CreateRequestBuilder {
        self.config.setgroups_deny = setgroups_deny.into();
        self
    }

    pub fn set_process_resource_limits(
        mut self,
        prlimits: ProcessResourceLimits,
    ) -> CreateRequestBuilder {
        self.config.exec.process_limits = prlimits.into();
        self
    }

    pub fn push_resource_limit(mut self, key: &str, value: &str) -> CreateRequestBuilder {
        if self.config.limits.is_none() {
            self.config.limits = BTreeMap::new().into();
        }

        if let Some(ref mut map) = self.config.limits {
            map.insert(key.to_string(), value.to_string());
        }

        self
    }

    pub fn push_environment(mut self, key: &str, value: &str) -> CreateRequestBuilder {
        if self.config.exec.environment.is_none() {
            self.config.exec.environment = BTreeMap::new().into();
        }

        if let Some(ref mut map) = self.config.exec.environment {
            map.insert(key.to_string(), value.to_string());
        }

        self
    }

    pub fn push_namespace(mut self, ns: Namespace) -> CreateRequestBuilder {
        if self.config.namespaces.is_none() {
            self.config.namespaces = vec![].into();
        }

        if let Some(ref mut nsset) = self.config.namespaces {
            nsset.push(ns);
        }

        self
    }

    pub fn push_uid_mapping(mut self, mapping: IdMapping) -> CreateRequestBuilder {
        if self.config.uid_mappings.is_none() {
            self.config.uid_mappings = vec![].into();
        }

        if let Some(ref mut map) = self.config.uid_mappings {
            map.push(mapping);
        }

        self
    }

    pub fn push_gid_mapping(mut self, mapping: IdMapping) -> CreateRequestBuilder {
        if self.config.gid_mappings.is_none() {
            self.config.gid_mappings = vec![].into();
        }

        if let Some(ref mut map) = self.config.gid_mappings {
            map.push(mapping);
        }

        self
    }

    pub fn push_mount(mut self, spec: MountSpec) -> CreateRequestBuilder {
        if self.config.mounts.is_none() {
            self.config.mounts = vec![].into();
        }

        if let Some(ref mut mounts) = self.config.mounts {
            mounts.push(spec);
        }

        self
    }

    pub fn push_mutation(mut self, spec: Mutation) -> CreateRequestBuilder {
        if self.config.mutations.is_none() {
            self.config.mutations = vec![].into();
        }

        if let Some(ref mut mutations) = self.config.mutations {
            mutations.push(spec);
        }

        self
    }

    pub fn push_raise_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.raise,
        );
        self
    }

    pub fn push_raise_ambient_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.raise_ambient,
        );
        self
    }

    pub fn push_drop_capability(mut self, cap: impl AsRef<str>) -> Self {
        add_to_cap_list(
            cap.as_ref().to_string(),
            &mut self.config.capabilities,
            |caps| &mut caps.drop,
        );
        self
    }

    pub fn to_request(self) -> CreateRequest {
        self.config
    }
}

#[derive(Debug)]
pub struct Runner {
    executable: String,
}

impl Runner {
    pub fn new(executable: &str) -> Runner {
        Runner {
            executable: executable.to_string(),
        }
    }

    fn write_config<T: Configurable>(&self, config: T, config_file: &mut TempFile) -> Result<()> {
        config.validate()?;

        let encap_config = config.encapsulate()?;

        // BufWriter doesn't actually flush the buffer until it is dropped.  Ugh.
        {
            let mut config_writer = BufWriter::new(&mut *config_file);
            serde_json::to_writer(&mut config_writer, &encap_config)?;
        }

        config_file.flush()?;

        Ok(())
    }

    fn create_command(&self, config_file: &TempFile) -> Result<Command> {
        let mut command = Command::new(&self.executable);
        let config_path = config_file.path().to_string();
        command.arg(config_path);
        Ok(command)
    }

    #[cfg(feature = "async")]
    fn create_command_async(&self, config_file: &TempFile) -> Result<tokio::process::Command> {
        let mut command = tokio::process::Command::new(&self.executable);
        let config_path = config_file.path().to_string();
        command.arg(config_path);
        Ok(command)
    }

    /// Run the specified container.
    /// Returns exit code on success, else error.
    pub fn run<T: Configurable>(&self, config: T) -> Result<i32> {
        let mut config_file = TempFile::new("styrolite-cfg-", ".json")?;
        self.write_config(config, &mut config_file)?;

        let status = self.create_command(&config_file)?.status()?;
        if let Some(code) = status.code() {
            return Ok(code);
        }

        Err(anyhow!("failed to launch/monitor child process"))
    }

    #[cfg(feature = "async")]
    pub async fn run_async<T: Configurable>(&self, config: T) -> Result<i32> {
        let mut config_file = TempFile::new("styrolite-cfg-", ".json")?;
        self.write_config(config, &mut config_file)?;

        let status = self.create_command_async(&config_file)?.status().await?;
        if let Some(code) = status.code() {
            return Ok(code);
        }

        Err(anyhow!("failed to launch/monitor child process"))
    }

    /// Replace the current process with the styrolite runner directly.
    #[cfg(unix)]
    pub fn exec<T: Configurable>(&self, config: T) -> Result<()> {
        let mut config_file = TempFile::new("styrolite-cfg-", ".json")?;
        self.write_config(config, &mut config_file)?;

        // Build the command like before
        let mut command = self.create_command(&config_file)?;

        // NOTE: If exec succeeds, this process image is replaced; no destructors run.
        // That means config_file won't be dropped, so a drop-based cleanup won't happen.
        // If TempFile is delete-on-drop, the file may be left behind.
        let err = command.exec(); // only returns on failure
        Err(anyhow!(err))
    }

    #[cfg(not(unix))]
    pub fn exec<T: Configurable>(&self, config: T) -> Result<()> {
        let _ = config;
        Err(anyhow!("Runner::exec is only supported on unix"))
    }
}
