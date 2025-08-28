use libc;

use std::env;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::{Error, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process;
use std::ptr;

use crate::caps::{CapabilityBit, get_caps, set_caps};
use crate::cgroup::CGroup;
use crate::config::{
    AttachRequest, Capabilities, CreateDirMutation, CreateRequest, ExecutableSpec, IdMapping,
    MountSpec, Mountable, Mutatable, Mutation, Wrappable,
};
use crate::namespace::Namespace;
use crate::unshare::{setns, unshare};
use anyhow::{Result, anyhow, bail};
use libc::{PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, PR_CAP_AMBIENT_RAISE, c_int, prctl};
use log::{debug, warn};

// We have to do this because the libc crate does not consistently provide
// bindings for setrlimit(2).  Non-GNU uses signed i32 for resource enums,
// while GNU uses __rlimit_resource_t which is unsigned.  Technically,
// the unsigned version is the correct one, but POSIX has made such a mess
// of the getrlimit(2) and setrlimit(2) interfaces that there really isn't
// any point in arguing either way.
#[cfg(target_env = "gnu")]
type RLimit = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RLimit = libc::c_int;

fn set_process_limit(resource: RLimit, limit: Option<u64>) -> Result<()> {
    let unpacked_limit = if let Some(rl) = limit {
        rl
    } else {
        libc::RLIM_INFINITY
    };

    let rlimit = libc::rlimit {
        rlim_cur: unpacked_limit,
        rlim_max: unpacked_limit,
    };

    unsafe {
        if libc::setrlimit(resource, &rlimit) == -1 {
            Err(anyhow!("failed to set resource limit"))
        } else {
            Ok(())
        }
    }
}

fn wait_for_pid(pid: libc::pid_t) -> Result<i32> {
    let status = unsafe {
        let mut st: MaybeUninit<i32> = MaybeUninit::uninit();

        if libc::waitpid(pid, st.as_mut_ptr(), 0) < 0 {
            panic!("waitpid of child process failed");
        }

        st.assume_init()
    };

    let exitcode = libc::WEXITSTATUS(status);
    Ok(exitcode)
}

fn fork_and_wait() -> Result<()> {
    let pid = unsafe { libc::fork() };
    if pid > 0 {
        debug!("child pid = {pid}");
        let exitcode = wait_for_pid(pid)?;
        debug!("[pid {pid}] exitcode = {exitcode}");
        process::exit(exitcode);
    }

    Ok(())
}

/// Find the first child PID of the given parent process.
///
/// The reason we need this is because we actually need to attach to the
/// *supervised* process, not the *supervisor* process, which exists in
/// a different set of namespaces than the ones we want to attach to.
fn first_child_pid_of(parent: libc::pid_t) -> Result<libc::pid_t> {
    let child_set = fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))?;
    let first_child = child_set.split(" ").collect::<Vec<_>>()[0];

    match first_child.parse::<libc::pid_t>() {
        Ok(v) => Ok(v),
        _ => Err(anyhow!("failed to find child PID")),
    }
}

fn render_uidgid_mappings(mappings: &[IdMapping]) -> String {
    mappings
        .iter()
        .map(|mapping| {
            format!(
                "{} {} {}",
                mapping.base_nsid, mapping.base_hostid, mapping.remap_count
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
}

impl CreateRequest {
    fn get_boottime(&self) -> i64 {
        unsafe {
            let mut ts: MaybeUninit<libc::timespec> = MaybeUninit::uninit();
            if libc::clock_gettime(libc::CLOCK_BOOTTIME, ts.as_mut_ptr()) < 0 {
                return 0;
            }
            let res = ts.assume_init();
            res.tv_sec
        }
    }

    fn update_boottime(&self) -> Result<()> {
        let boot_time = self.get_boottime() - 1;
        let boot_time = if boot_time <= 0 {
            "0".to_string()
        } else {
            format!("-{boot_time}")
        };
        let timecfg = format!("boottime {boot_time} 0\n");
        fs::write("/proc/self/timens_offsets", timecfg.as_bytes())?;
        Ok(())
    }

    fn prepare_userns(&self, pid: libc::pid_t) -> Result<()> {
        if let Some(uid_mappings) = &self.uid_mappings {
            fs::write(
                format!("/proc/{pid}/uid_map"),
                render_uidgid_mappings(uid_mappings),
            )?;
        }

        let sgd = self.setgroups_deny.unwrap_or(true);
        if sgd {
            fs::write(format!("/proc/{pid}/setgroups"), "deny".as_bytes())?;
        }

        if let Some(gid_mappings) = &self.gid_mappings {
            fs::write(
                format!("/proc/{pid}/gid_map"),
                render_uidgid_mappings(gid_mappings),
            )?;
        }

        Ok(())
    }

    fn identity(&self) -> Result<String> {
        let pid = process::id();

        match &self.workload_id {
            Some(wid) => Ok(wid.to_string()),
            None => {
                warn!("workload identity not set, using supervisor pid {pid} as identity");
                Ok(format!("{pid}"))
            }
        }
    }

    fn update_hostname(&self) -> Result<()> {
        let wid = self
            .identity()
            .expect("unable to determine a workload identity");
        let final_hostname = match &self.hostname {
            Some(hostname) => hostname.to_string(),
            None => format!("litewrap-{wid}"),
        };
        let final_hostname_cstr =
            CString::new(final_hostname).expect("unable to parse hostname as valid C string");
        let final_hostname_ptr = final_hostname_cstr.as_ptr();

        unsafe {
            if libc::sethostname(final_hostname_ptr, final_hostname_cstr.count_bytes()) < 0 {
                Err(anyhow!("failed to set hostname"))
            } else {
                Ok(())
            }
        }
    }

    fn prepare_cgroup(&self) -> Result<()> {
        if self.limits.is_none() {
            return Ok(());
        }

        let pid = process::id();
        let cgbase = self
            .cgroupfs
            .clone()
            .unwrap_or("/sys/fs/cgroup".to_string());
        let cgroot = CGroup::open(&cgbase)?;
        let subtree = cgroot.create_child(format!("litewrap-{}", self.identity()?))?;
        let limits = self.limits.clone().unwrap();

        let _: Vec<_> = limits
            .into_iter()
            .map(|(k, v)| {
                debug!("configuring resource limit {k} = {v}");
                match subtree.clone().set_child_value(&k, &v) {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("unable to set resource limit '{k}': {e:?}");
                    }
                }
            })
            .collect();

        debug!("binding supervisor (pid {pid}) to cgroup");
        subtree
            .clone()
            .set_child_value("cgroup.procs", &format!("{pid}"))?;

        Ok(())
    }

    fn pivot_fs(&self) -> Result<()> {
        debug!("early mount!");

        let rootfs = self
            .rootfs
            .clone()
            .expect("expected rootfs to be configured");

        // Unshare rootfs mount so we can later pivot to a new rootfs.
        // The unshared root mount will be cleaned up once the new rootfs is
        // in place.
        let oldroot = MountSpec {
            source: None,
            target: "/".to_string(),
            fstype: None,
            bind: false,
            recurse: true,
            unshare: true,
            safe: false,
            create_mountpoint: false,
        };

        oldroot
            .mount()
            .expect("failed to unshare / in new mount namespace");

        // Now mount the new rootfs.
        let newroot = MountSpec {
            source: Some(rootfs.clone()),
            target: rootfs.clone(),
            fstype: Some("none".to_string()),
            bind: true,
            recurse: true,
            unshare: false,
            safe: false,
            create_mountpoint: false,
        };

        newroot.mount().expect("failed to bind new rootfs");

        // Mount /proc.
        let procfs = MountSpec {
            source: Some("proc".to_string()),
            target: format!("{rootfs}/proc"),
            fstype: Some("proc".to_string()),
            bind: false,
            recurse: true,
            unshare: false,
            safe: true,
            create_mountpoint: false,
        };

        procfs.mount().expect("failed to mount /proc");

        if let Some(mounts) = &self.mounts {
            for mount in mounts {
                let parented_target = format!("{}/{}", rootfs, mount.target);
                let parented_mount = MountSpec {
                    source: mount.source.clone(),
                    target: parented_target.clone(),
                    fstype: mount.fstype.clone(),
                    bind: mount.bind,
                    recurse: mount.recurse,
                    unshare: mount.unshare,
                    safe: mount.safe,
                    create_mountpoint: mount.create_mountpoint,
                };

                parented_mount
                    .mount()
                    .expect("failed to process mount spec");
            }
        }

        if let Some(mutations) = &self.mutations {
            for mutation in mutations {
                match mutation {
                    Mutation::CreateDir(cdm) => {
                        cdm.mutate(&rootfs).expect("failed to create directory");
                    }
                };
            }
        }

        newroot.pivot().expect("failed to pivot to new rootfs");

        Ok(())
    }
}

impl Wrappable for CreateRequest {
    /// Execute a process according to the wrap config specified.
    /// This function should eventually result in an execve.
    /// All streams of stdin/stdout/stderr that were requested in the config
    /// should be bound to the corresponding litewrap process fds.
    /// For simplicity, the zone workload management handles ptys.
    /// If a tty is needed, it will be connected to this process already. Error handling should bubble up.
    ///
    /// Exit code of this process should match the exit code of the process to run.
    /// For simplicity, litewrap should not currently act as a reaper. tini can do that for now.
    fn wrap(&self) -> Result<()> {
        debug!("executing with config {self:?}");

        let target_ns = self.namespaces.clone().unwrap_or(vec![
            Namespace::Mount,
            Namespace::Time,
            Namespace::Uts,
            Namespace::Pid,
            Namespace::Ipc,
            Namespace::User,
        ]);

        debug!("namespaces: {target_ns:?}");

        debug!(
            "maybe create a new supervisor cgroup for workload identity {}",
            self.identity()?
        );
        if self.prepare_cgroup().is_err() {
            warn!("unable to set resource limits, cgroup access denied!");
        }

        let first_level_ns = target_ns
            .iter()
            .filter(|ns| **ns != Namespace::User)
            .cloned()
            .collect::<Vec<_>>();

        debug!("unsharing namespaces");
        unshare(&first_level_ns)?;

        debug!("update boot time");
        if self.update_boottime().is_err() {
            warn!("unable to update boot time");
        }

        debug!("setting hostname");
        if self.update_hostname().is_err() {
            warn!("unable to set hostname");
        }

        debug!("setting process limits");
        if self.exec.set_process_limits().is_err() {
            warn!("unable to set process limits");
        }

        debug!("all namespaces unshared -- forking child");
        let parent_efd = unsafe { libc::eventfd(0, libc::EFD_SEMAPHORE) };
        let child_efd = unsafe { libc::eventfd(0, libc::EFD_SEMAPHORE) };
        let pid = unsafe { libc::fork() };
        if pid > 0 {
            debug!("child pid = {pid}");
            let mut pef = unsafe { File::from_raw_fd(parent_efd) };
            debug!("parent efd = {parent_efd}");
            debug!("child efd = {child_efd}");
            let mut buf = [0u8; 8];
            pef.read_exact(&mut buf)?;

            if target_ns.contains(&Namespace::User) {
                // We are preparing the userns for PID 1 because we are in the same mount namespace
                // as the child, and thus the first process created is always PID 1.  We no longer
                // have access to the host /proc so we just hardcode PID 1 and hope for the best.
                // So far, this seems to work fairly well.
                debug!("child has dropped into its own userns, configuring from supervisor");
                self.prepare_userns(1)?;
            }

            // The supervisor has now configured the user namespace, so let the first process run.
            let mut cef = unsafe { File::from_raw_fd(child_efd) };
            cef.write_all(&1_u64.to_ne_bytes())?;

            let exitcode = wait_for_pid(pid)?;
            debug!("[pid {pid}] exitcode = {exitcode}");
            process::exit(exitcode);
        }

        if target_ns.contains(&Namespace::Mount) {
            self.pivot_fs()?;
        } else {
            warn!("mount namespace not present in requested namespaces, trying to work anyway...");
            warn!("this is an insecure configuration!");
        }

        debug!("mount tree finalized, doing final prep");
        let mut pef = unsafe { File::from_raw_fd(parent_efd) };

        if target_ns.contains(&Namespace::User) {
            debug!("unsharing user namespace");
            unshare(&vec![Namespace::User])?;
        }

        apply_capabilities(self.capabilities.as_ref())?;

        debug!("signalling supervisor to do configuration");
        pef.write_all(&2_u64.to_ne_bytes())?;
        pef.flush()?;

        // Wait for completion from the supervisor before launching the initial process
        // for this container.
        let mut cef = unsafe { File::from_raw_fd(child_efd) };
        let mut buf = [0u8; 8];
        cef.read_exact(&mut buf)?;

        debug!("ready to launch workload");
        self.exec.execute()
    }
}

impl ExecutableSpec {
    fn execute(&self) -> Result<()> {
        let executable = self
            .executable
            .clone()
            .expect("expected executable to be configured");

        let program_cstring = CString::new(executable)?;
        let mut args_cstrings: Vec<_> = if let Some(args) = &self.arguments {
            args.clone()
                .into_iter()
                .map(|arg| CString::new(arg.as_bytes()))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };
        args_cstrings.insert(0, program_cstring.clone());
        let mut args_charptrs: Vec<_> = args_cstrings.iter().map(|arg| arg.as_ptr()).collect();
        args_charptrs.push(ptr::null());

        let env_cstrings: Vec<_> = if let Some(env) = &self.environment {
            env.clone()
                .into_iter()
                .map(|(key, value)| CString::new(format!("{key}={value}").as_bytes()))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };
        let mut env_charptrs: Vec<_> = env_cstrings.iter().map(|arg| arg.as_ptr()).collect();
        env_charptrs.push(ptr::null());

        if let Some(target_uid) = self.uid {
            unsafe {
                // Check this to avoid a spurious log if we don't need to change,
                // because we are already running as the target UID.
                if libc::getuid() != target_uid && libc::setuid(target_uid as libc::uid_t) < 0 {
                    warn!("unable to set target UID: {:?}", Error::last_os_error());
                }
            }
        }

        if let Some(target_gid) = self.gid {
            unsafe {
                // Check this to avoid a spurious log if we don't need to change,
                // because we are already running as the target GID.
                if libc::getgid() != target_gid && libc::setgid(target_gid as libc::gid_t) < 0 {
                    warn!("unable to set target GID: {:?}", Error::last_os_error());
                }
            }
        }

        if let Some(wd) = &self.working_directory {
            env::set_current_dir(wd.clone())?;
        }

        unsafe {
            if libc::execvpe(
                program_cstring.as_ptr(),
                args_charptrs.as_ptr(),
                env_charptrs.as_ptr(),
            ) < 0
            {
                Err(anyhow!("execvpe failed"))
            } else {
                Ok(())
            }
        }
    }

    fn set_process_limits(&self) -> Result<()> {
        if self.process_limits.is_none() {
            return Ok(());
        }

        let prlimits = self
            .process_limits
            .clone()
            .expect("process limits must be configured at this point");

        set_process_limit(libc::RLIMIT_AS, prlimits.address_space_size)?;
        set_process_limit(libc::RLIMIT_CORE, prlimits.core_size)?;
        set_process_limit(libc::RLIMIT_CPU, prlimits.cpu_time)?;
        set_process_limit(libc::RLIMIT_DATA, prlimits.data_space_size)?;
        set_process_limit(libc::RLIMIT_FSIZE, prlimits.file_size)?;
        set_process_limit(libc::RLIMIT_MEMLOCK, prlimits.locked_space_size)?;
        set_process_limit(libc::RLIMIT_MSGQUEUE, prlimits.msgqueue_size)?;
        set_process_limit(libc::RLIMIT_NICE, prlimits.nice_ceiling)?;
        set_process_limit(libc::RLIMIT_NOFILE, prlimits.open_files)?;
        set_process_limit(libc::RLIMIT_NPROC, prlimits.thread_limit)?;
        set_process_limit(libc::RLIMIT_RSS, prlimits.resident_space_size)?;
        set_process_limit(libc::RLIMIT_RTPRIO, prlimits.real_time_priority)?;
        set_process_limit(libc::RLIMIT_RTTIME, prlimits.real_time_limit)?;
        set_process_limit(libc::RLIMIT_SIGPENDING, prlimits.pending_signal_limit)?;
        set_process_limit(libc::RLIMIT_STACK, prlimits.main_thread_stack_size)?;

        Ok(())
    }
}

impl AttachRequest {
    fn identity(&self) -> Result<String> {
        let pid = process::id();

        match &self.workload_id {
            Some(wid) => Ok(wid.to_string()),
            None => {
                warn!("workload identity not set, using supervisor pid {pid} as identity");
                Ok(format!("{pid}"))
            }
        }
    }

    fn attach_cgroup(&self) -> Result<()> {
        let pid = process::id();
        let cgbase = self
            .cgroupfs
            .clone()
            .unwrap_or("/sys/fs/cgroup".to_string());
        let cgroot = CGroup::open(&cgbase)?;
        let subtree = cgroot.create_child(format!("litewrap-{}", self.identity()?))?;

        debug!("binding supervisor (pid {pid}) to cgroup");
        subtree
            .clone()
            .set_child_value("cgroup.procs", &format!("{pid}"))?;

        Ok(())
    }
}

impl Wrappable for AttachRequest {
    fn wrap(&self) -> Result<()> {
        debug!("executing with config {self:?}");

        let target_ns = self.namespaces.clone().unwrap_or(vec![
            Namespace::Mount,
            Namespace::Time,
            Namespace::Uts,
            Namespace::Pid,
            Namespace::Ipc,
            Namespace::User,
        ]);

        debug!("namespaces: {target_ns:?}");

        let target_pid = first_child_pid_of(self.pid)?;

        debug!(
            "maybe attach to a pre-existing supervisor cgroup for workload identity {}",
            self.identity()?
        );
        if self.attach_cgroup().is_err() {
            warn!("unable to set resource limits, cgroup access denied!");
        }

        debug!("determined that we want to use the namespaces of host PID {target_pid}");
        setns(target_pid, &target_ns)?;

        debug!("setting process limits");
        if self.exec.set_process_limits().is_err() {
            warn!("unable to set process limits");
        }

        apply_capabilities(self.capabilities.as_ref())?;

        debug!("all namespaces joined -- forking child");
        fork_and_wait()?;

        self.exec.execute()
    }
}

// TODO(kaniini): Move the mutations to their own rust sources.
impl Mutatable for CreateDirMutation {
    fn mutate(&self, rootfs: &str) -> Result<()> {
        let mut path = PathBuf::from(rootfs);
        path.push(self.target.clone());

        Ok(fs::create_dir_all(path)?)
    }
}

fn apply_capabilities(capabilities: Option<&Capabilities>) -> Result<()> {
    let Some(caps) = capabilities else {
        return Ok(());
    };

    debug!("setting process capabilities");
    let mut current_capabilities = get_caps()?;
    let drops = Capabilities::names_as_bits(caps.drop.as_deref().unwrap_or(&[]))?;
    let raises = Capabilities::names_as_bits(caps.raise.as_deref().unwrap_or(&[]))?;
    let raises_ambient = Capabilities::names_as_bits(caps.raise_ambient.as_deref().unwrap_or(&[]))?;

    current_capabilities.effective =
        CapabilityBit::clear_bits(current_capabilities.effective, &drops);
    current_capabilities.effective =
        CapabilityBit::set_bits(current_capabilities.effective, &raises);
    current_capabilities.permitted = current_capabilities.effective;
    current_capabilities.inheritable = current_capabilities.effective;
    set_caps(current_capabilities)?;

    for drop in &drops {
        let error = unsafe {
            prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_LOWER,
                drop.to_cap_number() as c_int,
                0,
                0,
            )
        };
        if error != 0 {
            bail!(
                "failed to drop ambient capability: {}",
                Error::last_os_error()
            );
        }
    }

    for raise in &raises_ambient {
        let error = unsafe {
            prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                raise.to_cap_number() as c_int,
                0,
                0,
            )
        };
        if error != 0 {
            bail!(
                "failed to raise ambient capability: {}",
                Error::last_os_error()
            );
        }
    }
    Ok(())
}
