use std::env;
use std::ffi::CString;
use std::fs;
use std::io::Error;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::process;
use std::ptr;

use crate::caps::{CapabilityBit, get_caps, set_caps, set_keep_caps};
use crate::cgroup::CGroup;
use crate::config::{
    AttachRequest, Capabilities, CreateDirMutation, CreateRequest, ExecutableSpec, IdMapping,
    MountSpec, Mountable, Mutatable, Mutation, Wrappable,
};
use crate::namespace::Namespace;
use crate::signal;
use crate::unshare::{setns, unshare};
use anyhow::Context;
use anyhow::{Result, anyhow, bail};
use libc::{
    self, PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, PR_CAP_AMBIENT_RAISE, PR_CAPBSET_DROP,
    PR_SET_NO_NEW_PRIVS, c_int, prctl,
};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};

use log::{debug, error, warn};

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
            Err(anyhow!(
                "failed to set resource limit {resource}: {}",
                Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }
}

fn reap_children() -> Result<()> {
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            _ => {}
        }
    }
    Ok(())
}

fn wait_for_pid(pid: libc::pid_t) -> Result<i32> {
    match waitpid(Pid::from_raw(pid), None)? {
        WaitStatus::Exited(_, code) => Ok(code),
        _ => Ok(1),
    }
}

fn fork_and_wait() -> Result<()> {
    if let Err(e) = unsafe { signal::setup_parent_signal_handlers() } {
        warn!("unable to set up parent signal handlers: {e}");
        process::exit(1)
    }

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            signal::store_child_pid(child.as_raw());
            debug!("child pid = {}", child.as_raw());
            let exitcode = wait_for_pid(child.as_raw())?;
            debug!("[pid {}] exitcode = {exitcode}", child.as_raw());
            debug!("reaping children of supervisor!");
            reap_children()?;
            process::exit(exitcode);
        }
        ForkResult::Child => {}
    }

    if let Err(e) = unsafe { signal::reset_child_signal_handlers() } {
        error!("Failed to reset child signal handlers: {e}");
        process::exit(1);
    }

    Ok(())
}

/// Find the first child PID of the given parent process.
///
/// The reason we need this is because we actually need to attach to the
/// *supervised* process, not the *supervisor* process, which exists in
/// a different set of namespaces than the ones we want to attach to.
///
/// Tries `/proc/<pid>/task/<pid>/children` first (requires CONFIG_PROC_CHILDREN),
/// then falls back to scanning `/proc` for processes whose PPid matches.
fn first_child_pid_of(parent: libc::pid_t) -> Result<libc::pid_t> {
    // Fast path: use the children file if available (CONFIG_PROC_CHILDREN=y).
    let children_path = format!("/proc/{parent}/task/{parent}/children");
    if let Ok(child_set) = fs::read_to_string(&children_path) {
        let first_child = child_set.split(' ').next().unwrap_or("");
        if let Ok(v) = first_child.parse::<libc::pid_t>() {
            return Ok(v);
        }
    }

    // Fallback: scan /proc for a process whose PPid matches parent.
    debug!("children file unavailable for pid {parent}, falling back to /proc scan");
    let ppid_needle = format!("PPid:\t{parent}");
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let status_path = format!("/proc/{name_str}/status");
        if let Ok(status) = fs::read_to_string(&status_path)
            && status.lines().any(|line| line == ppid_needle)
            && let Ok(pid) = name_str.parse::<libc::pid_t>()
        {
            return Ok(pid);
        }
    }

    Err(anyhow!("failed to find child PID of {parent}"))
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
            None => format!("styrolite-{wid}"),
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
        // If we haven't been given a cgroup OR limits, nothing to do here.
        if self.limits.is_none() && self.cgroupfs.is_none() {
            debug!("skipping prepare_cgroup");
            return Ok(());
        }

        debug!(
            "prepare_cgroup - limits: {:?} cgroupfs: {:?}",
            self.limits, self.cgroupfs
        );
        let pid = process::id();
        let cgbase = self
            .cgroupfs
            .clone()
            .unwrap_or("/sys/fs/cgroup".to_string());
        let cgroot = CGroup::open(&cgbase)?;

        if let Some(limits) = self.limits.clone() {
            // if we have been given limits and a cgroup, create a subtree cgroup,
            // set limits on it, and move ourselves into it.

            // Ensure the correct controllers are enabled for limits we want to set
            // in our subtree, and attempt to enable them if not.
            let controller_string = limits
                .keys()
                .filter_map(|key| {
                    key.split('.')
                        .next()
                        .filter(|prefix| matches!(*prefix, "cpu" | "memory" | "io" | "pids"))
                })
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .map(|c| format!("+{}", c))
                .collect::<Vec<_>>()
                .join(" ");

            if !controller_string.is_empty() {
                debug!(
                    "enabling controllers in provided cgroup: {}",
                    controller_string
                );

                if let Err(e) = cgroot
                    .clone()
                    .set_child_value("cgroup.subtree_control", &controller_string)
                {
                    warn!("could not enable controllers in provided cgroup: {e:?}");
                }
            }

            let subtree = cgroot.create_child(format!("styrolite-{}", self.identity()?))?;

            let _: Vec<_> = limits
                .into_iter()
                .map(|(k, v)| {
                    if k.starts_with("cgroup.") {
                        warn!("attempt to set invalid resource limit '{k}' was blocked");
                        return;
                    }

                    debug!("configuring resource limit {k} = {v}");
                    match subtree.clone().set_child_value(&k, &v) {
                        Ok(_) => (),
                        Err(e) => {
                            warn!("unable to set resource limit '{k}': {e:?}");
                        }
                    }
                })
                .collect();
            debug!(
                "binding supervisor (pid {pid}) to subtree cgroup: {:?}",
                subtree
            );
            subtree
                .clone()
                .set_child_value("cgroup.procs", &format!("{pid}"))?;
        } else {
            // if we have been given a cgroup and *no* limits, just make sure we
            // move ourselves into it.
            debug!("binding supervisor (pid {pid}) to cgroup: {:?}", cgroot);
            cgroot.set_child_value("cgroup.procs", &format!("{pid}"))?;
        }

        Ok(())
    }

    fn pivot_fs(&self) -> Result<()> {
        debug!("early mount!");

        let mut rootfs = self
            .rootfs
            .clone()
            .ok_or_else(|| anyhow!("expected rootfs to be configured"))?;

        let rootfs_readonly = self.rootfs_readonly.unwrap_or(false);

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
            read_only: false,
            data: None,
        };

        oldroot
            .mount()
            .map_err(|e| anyhow!("failed to unshare / in new mount namespace: {e}"))?;

        // If we want to clone the VFS root, e.g. for styrojail,
        // we have to do some special things to cope with that.
        let stage_base = format!("/tmp/styrolite-stage-{}", self.identity()?);
        let stage_root = format!("/tmp/styrolite-stage-{}/root", self.identity()?);
        let stage_old = format!("/tmp/styrolite-stage-{}/old", self.identity()?);

        if rootfs == "/" {
            // Mount a tmpfs staging area so we can pivot into a non-"/" mountpoint.
            let stage_tmpfs = MountSpec {
                source: Some("tmpfs".to_string()),
                target: stage_base,
                fstype: Some("tmpfs".to_string()),
                bind: false,
                recurse: false,
                unshare: false,
                safe: true,
                create_mountpoint: true,
                read_only: false,
                data: None,
            };
            stage_tmpfs
                .mount()
                .map_err(|e| anyhow!("failed to mount staging tmpfs: {e}"))?;

            fs::create_dir_all(&stage_root)
                .map_err(|e| anyhow!("failed to create staging root dir: {e}"))?;
            fs::create_dir_all(&stage_old)
                .map_err(|e| anyhow!("failed to create staging old dir: {e}"))?;

            let stage_bind = MountSpec {
                source: Some("/".to_string()),
                target: stage_root.clone(),
                fstype: Some("none".to_string()),
                bind: true,
                recurse: true,
                unshare: false,
                safe: false,
                create_mountpoint: false,
                read_only: false,
                data: None,
            };
            stage_bind
                .mount()
                .map_err(|e| anyhow!("failed to bind / into staging root: {e}"))?;

            rootfs = stage_root.to_string();
        }

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
            read_only: false,
            data: None,
        };

        newroot
            .mount()
            .map_err(|e| anyhow!("failed to bind new rootfs: {e}"))?;

        if rootfs_readonly {
            newroot
                .seal()
                .map_err(|e| anyhow!("failed to make new rootfs readonly: {e}"))?;
        }

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
            read_only: false,
            data: None,
        };

        procfs
            .mount()
            .map_err(|e| anyhow!("failed to mount /proc: {e}"))?;

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
                    read_only: mount.read_only,
                    data: None,
                };

                parented_mount
                    .mount()
                    .map_err(|e| anyhow!("failed to process mount spec {parented_target}: {e}"))?;
            }
        }

        if let Some(mutations) = &self.mutations {
            for mutation in mutations {
                match mutation {
                    Mutation::CreateDir(cdm) => {
                        cdm.mutate(&rootfs)
                            .map_err(|e| anyhow!("failed to create directory: {e}"))?;
                    }
                };
            }
        }

        // Apply OCI-style path hardening after every mount is in place (so
        // freshly-mounted targets such as /proc are covered) but before pivot,
        // while /dev/null is still reachable for masking. Targets are resolved
        // under the new rootfs; missing ones are skipped.
        if let Some(masked) = &self.masked_paths {
            for path in masked {
                crate::mount::mask_path(&rootfs, path)
                    .map_err(|e| anyhow!("failed to mask {path}: {e}"))?;
            }
        }
        if let Some(readonly) = &self.readonly_paths {
            for path in readonly {
                crate::mount::make_readonly(&rootfs, path)
                    .map_err(|e| anyhow!("failed to make {path} read-only: {e}"))?;
            }
        }

        newroot
            .pivot()
            .map_err(|e| anyhow!("failed to pivot to new rootfs: {e}"))?;

        Ok(())
    }
}

impl Wrappable for CreateRequest {
    /// Execute a process according to the wrap config specified.
    /// This function should eventually result in an execve.
    /// All streams of stdin/stdout/stderr that were requested in the config
    /// should be bound to the corresponding styrolite process fds.
    /// For simplicity, the zone workload management handles ptys.
    /// If a tty is needed, it will be connected to this process already. Error handling should bubble up.
    ///
    /// Exit code of this process should match the exit code of the process to run.
    /// For simplicity, styrolite should not currently act as a reaper. tini can do that for now.
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
        if let Err(e) = self.prepare_cgroup() {
            warn!("unable to prepare cgroup: {e}");
        }

        let skip_two_stage_userns = self.skip_two_stage_userns.unwrap_or(false);

        let first_level_ns = if !skip_two_stage_userns {
            target_ns
                .iter()
                .filter(|ns| **ns != Namespace::User)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            target_ns.clone()
        };

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

        debug!("setting up parent signal handlers");
        if let Err(e) = unsafe { signal::setup_parent_signal_handlers() } {
            warn!("unable to set up parent signal handlers: {e}");
            process::exit(1)
        }

        debug!("all namespaces unshared -- forking child");
        let parent_efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE)?;
        let child_efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE)?;
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                signal::store_child_pid(child.as_raw());

                debug!("child pid = {}", child.as_raw());
                parent_efd.read()?;

                if target_ns.contains(&Namespace::User) {
                    debug!("child has dropped into its own userns, configuring from supervisor");
                    // In the two-stage path, the child calls pivot_fs() before signaling.
                    // pivot_root() changes /proc for the parent too.
                    // If a PID namespace was created, the new /proc shows the child as PID 1
                    // (not its host PID), so we must use 1 to find it in /proc.
                    // Without a PID namespace, the new proc mount still shows global PIDs.
                    let userns_pid =
                        if !skip_two_stage_userns && target_ns.contains(&Namespace::Pid) {
                            1
                        } else {
                            child.as_raw()
                        };
                    self.prepare_userns(userns_pid)?;
                }

                // The supervisor has now configured the user namespace, so let the first process run.
                child_efd.write(1)?;

                let exitcode = wait_for_pid(child.as_raw())?;
                debug!("[pid {}] exitcode = {exitcode}", child.as_raw());

                debug!("reaping children of supervisor!");
                reap_children()?;

                process::exit(exitcode);
            }
            ForkResult::Child => {}
        }

        if let Err(e) = unsafe { signal::reset_child_signal_handlers() } {
            error!("Failed to reset child signal handlers: {e}");
            process::exit(1);
        }

        if !skip_two_stage_userns {
            // The mount namespace was unshared in the parent under the initial user
            // namespace context. Mount operations must happen before we enter the new
            // user namespace, otherwise the child's user namespace won't own the mount
            // namespace and operations on it will fail with EPERM.
            if target_ns.contains(&Namespace::Mount) {
                self.pivot_fs()?;
            } else {
                warn!(
                    "mount namespace not present in requested namespaces, trying to work anyway..."
                );
                warn!("this is an insecure configuration!");
            }

            if target_ns.contains(&Namespace::User) {
                debug!("unsharing user namespace");
                unshare(&vec![Namespace::User])?;
            }
        }

        debug!("signalling supervisor to do configuration");
        parent_efd.write(2)?;

        // Wait for completion from the supervisor before launching the initial process
        // for this container.
        child_efd.read()?;

        if skip_two_stage_userns {
            // In two-stage mode, mounts are deferred until after
            // UID/GID namespace has been configured by the supervisor.
            if target_ns.contains(&Namespace::Mount) {
                self.pivot_fs()?;
            } else {
                warn!(
                    "mount namespace not present in requested namespaces, trying to work anyway..."
                );
                warn!("this is an insecure configuration!");
            }
        }

        debug!("mount tree finalized, doing final prep");

        // Ensure the process receives the desired out-of-memory score adjustment.
        if let Some(score) = self.exec.oom_score_adj {
            fs::write("/proc/self/oom_score_adj", score.to_string())?;
        }

        // Bind the workload's terminal over /dev/console and hand the
        // workload uid ownership of it. We must do this here, after we have moved into
        // the mount/userns, but before we drop CAP_SYS_ADMIN/CAP_CHOWN.
        setup_console(self.exec.uid)?;

        preexec_prep(&self.exec, self.capabilities.as_ref())?;

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

        if let Some(wd) = &self.working_directory {
            env::set_current_dir(wd.clone())?;
        }

        if self.no_new_privs {
            self.set_no_new_privs()?;
        }

        if let Some(filter) = &self.seccomp {
            if !self.no_new_privs {
                bail!("seccomp filter requires no_new_privs = true");
            }
            unsafe { filter.install()? };
        }

        // The Rust runtime ignores SIGPIPE (SIG_IGN) process-wide, and that
        // disposition is inherited across execve. Restore SIG_DFL so the
        // workload sees the standard broken-pipe behaviour, matching runc/crun.
        signal::reset_sigpipe()?;

        unsafe {
            if libc::execvpe(
                program_cstring.as_ptr(),
                args_charptrs.as_ptr(),
                env_charptrs.as_ptr(),
            ) < 0
            {
                // execvpe only returns on failure. Capture errno immediately
                // (before any other libc call can clobber it) and translate it
                // into an actionable message. "execvpe failed" with no detail
                // has repeatedly sent people looking in the wrong place.
                let err = Error::last_os_error();
                let program = program_cstring.to_string_lossy();
                let hint = match err.raw_os_error() {
                    Some(libc::ENOENT) => format!(
                        " (is '{program}' installed and on PATH? if you meant to \
                         pass it as an argument, check the order of the executable \
                         and its arguments)"
                    ),
                    Some(libc::EACCES) => {
                        format!(" (is '{program}' marked executable, and are all \
                                 leading path components accessible?)")
                    }
                    Some(libc::ENOEXEC) => format!(
                        " (is '{program}' a valid executable for this architecture, \
                         or is it a script missing a #! interpreter line?)"
                    ),
                    _ => String::new(),
                };
                Err(anyhow!("failed to execute '{program}': {err}{hint}"))
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

    // Note that `PR_SET_NO_NEW_PRIVS` is *not* a foolproof privilege escalation
    // setting - it just "locks" the privilege set. If the process is granted
    // CAP_ADMIN or similar elsewhere, it is trivial to escalate privs in spite of this flag.
    fn set_no_new_privs(&self) -> Result<()> {
        let error = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if error != 0 {
            bail!(
                "failed to set no_new_privs flag: {}",
                Error::last_os_error()
            );
        }

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
        let name = format!("styrolite-{}", self.identity()?);

        let mut path = PathBuf::from(&cgbase);
        path.push(&name);

        if !path.exists() {
            return Ok(());
        }

        let path_str = path
            .to_str()
            .ok_or(anyhow!("path is somehow not valid utf-8"))?;
        let subtree = CGroup::open(path_str)?;

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

        // Ensure the process receives the desired out-of-memory score adjustment.
        if let Some(score) = self.exec.oom_score_adj {
            fs::write("/proc/self/oom_score_adj", score.to_string())?;
        }

        debug!("all namespaces joined -- forking child");
        fork_and_wait()?;

        preexec_prep(&self.exec, self.capabilities.as_ref())?;

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

fn apply_gid_uid(
    gid: Option<u32>,
    uid: Option<u32>,
    supplemental_gids: Option<&Vec<u32>>,
) -> Result<()> {
    // NOTE - order is important here - must change GID *before* changing UID, to avoid
    // locking oneself out of the GID change with an "operation not permitted" error
    if let Some(target_gid) = gid {
        unsafe {
            // Check this to avoid a spurious log if we don't need to change,
            // because we are already running as the target GID.
            if libc::getgid() != target_gid && libc::setgid(target_gid as libc::gid_t) < 0 {
                warn!("unable to set target GID: {:?}", Error::last_os_error());
            }
        }
    }

    // Set supplemental gids, if any. As with changing the primary gid, this must happen before the UID shift.
    if let Some(target_supplemental_gids) = supplemental_gids {
        unsafe {
            let gids_libc: Vec<libc::gid_t> = target_supplemental_gids
                .iter()
                .map(|g| *g as libc::gid_t)
                .collect();
            if libc::setgroups(gids_libc.len(), gids_libc.as_ptr()) < 0 {
                warn!(
                    "unable to set supplemental GIDs: {:?}",
                    Error::last_os_error()
                );
            }
        }
    }

    if let Some(target_uid) = uid {
        unsafe {
            // Check this to avoid a spurious log if we don't need to change,
            // because we are already running as the target UID.
            if libc::getuid() != target_uid && libc::setuid(target_uid as libc::uid_t) < 0 {
                warn!("unable to set target UID: {:?}", Error::last_os_error());
            }
        }
    }

    Ok(())
}

/// Similar to what runc and others do: if we have an exec UID override, bind a pty to /dev/console
/// with the correct UID ownership, so non-root stuff with that UID can open/write to console.
/// Note that we intentionally only do this for CreateRequest, where we control/create the mount namespace.
fn setup_console(uid: Option<u32>) -> Result<()> {
    // Only do the setup if we have an exec UID, otherwise there's no point.
    if let Some(exec_uid) = uid {
        let Some(tty_fd) = [0, 1, 2]
            .into_iter()
            .find(|fd| unsafe { libc::isatty(*fd) } == 1)
        else {
            return Ok(());
        };

        let pts_path =
            fs::read_link(format!("/proc/self/fd/{tty_fd}")).context("could not read TTY FD")?;

        // If /dev/console isn't here, we should be fine to create it and bind over it,
        // rather than bind over the existing one.
        if !std::path::Path::new("/dev/console").exists() {
            fs::File::create("/dev/console").context("could not create /dev/console stub")?;
        }

        let console_mount = MountSpec {
            source: Some(pts_path.to_string_lossy().into_owned()),
            target: "/dev/console".to_string(),
            fstype: None,
            bind: true,
            recurse: false,
            unshare: false,
            safe: false,
            create_mountpoint: false,
            read_only: false,
            data: None,
        };
        console_mount
            .mount()
            .context("failed to bind-mount /dev/console")?;

        // Flag the cases runc does:
        // - a uid not mapped into our userns (EPERM)
        // - a read-only /dev
        let rc = unsafe { libc::fchown(tty_fd, exec_uid as libc::uid_t, u32::MAX as libc::gid_t) };
        if rc < 0 {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EPERM) | Some(libc::EROFS) => {
                    warn!("refusing to chown workload console to uid {exec_uid}: {err}");
                }
                _ => bail!("failed to chown workload console to uid {exec_uid}: {err}"),
            }
        }
    }

    Ok(())
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

    for drop in &drops {
        if !raises.contains(drop) && !raises_ambient.contains(drop) {
            let error = unsafe { prctl(PR_CAPBSET_DROP, drop.to_cap_number() as c_int, 0, 0, 0) };
            if error != 0 {
                bail!(
                    "failed to drop bounding capability: {}",
                    Error::last_os_error()
                );
            }
        }
    }

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

/// The ordered final prep that runs after namespaces are set up and right
/// before execve(2). The sequence MUST be:
///
/// 1. `set_keep_caps` (SECBIT_NO_SETUID_FIXUP) so the kernel does not clear
///    the permitted/effective cap sets on a uid 0 <-> non-zero transition.
/// 2. `apply_gid_uid` to drop primary GID, supplemental GIDs, and UID.
/// 3. `apply_capabilities` to apply the workload's final cap raises/drops.
///
/// Both `CreateRequest::wrap` and `AttachRequest::wrap` must run this
/// sequence.
fn preexec_prep(exec: &ExecutableSpec, capabilities: Option<&Capabilities>) -> Result<()> {
    // We need to toggle SECBIT before we change UID/GID,
    // or else changing UID/GID may cause us to lose the capabilities
    // we need to explicitly drop capabilities later on.
    set_keep_caps()?;
    // Set these *first*, before we exec. Otherwise
    // we may not be able to switch after dropping caps.
    apply_gid_uid(exec.gid, exec.uid, exec.supplemental_gids.as_ref())?;
    // Now, we can synchronize effective/inherited/permitted caps
    // as a final step.
    apply_capabilities(capabilities)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_capabilities, apply_gid_uid, preexec_prep};
    use crate::caps::{CapabilityBit, get_caps};
    use crate::config::{Capabilities, CreateRequest, ExecutableSpec};
    use crate::namespace::Namespace;
    use crate::unshare::unshare;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, fork, geteuid};

    const NOBODY_UID: u32 = 65534;

    /// Run a closure in a forked child. Returns true if the child exits 0.
    /// Uses _exit() to skip Rust destructors in the child.
    unsafe fn in_child<F: FnOnce() -> i32>(f: F) -> bool {
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Child => unsafe { libc::_exit(f()) },
            ForkResult::Parent { child } => matches!(
                waitpid(child, None).expect("waitpid failed"),
                WaitStatus::Exited(_, 0)
            ),
        }
    }

    fn is_root() -> bool {
        geteuid().is_root()
    }

    /// Create a minimal rootfs with a /proc mountpoint for pivot_fs() tests.
    /// Returns the TempDir so the caller keeps it alive. Children use _exit()
    /// and never run its destructor; the parent drops it after waitpid().
    fn make_minimal_rootfs() -> Option<tempfile::TempDir> {
        let dir = tempfile::TempDir::new().ok()?;
        std::fs::create_dir_all(dir.path().join("proc")).ok()?;
        Some(dir)
    }

    fn request_with_rootfs(dir: &tempfile::TempDir) -> CreateRequest {
        CreateRequest {
            rootfs: Some(dir.path().to_string_lossy().into_owned()),
            workload_id: Some("test".to_string()),
            ..Default::default()
        }
    }

    /// Two-stage path (skip_two_stage_userns=false): mount namespace is unshared
    /// in the initial user namespace context (root). pivot_fs() must succeed BEFORE
    /// entering the new user namespace, because the mount namespace is owned by
    /// the initial user namespace.
    ///
    /// Root-only: creating a mount namespace in the initial user namespace context
    /// requires CAP_SYS_ADMIN there. An unprivileged user namespace unshare followed
    /// by a mount namespace unshare results in locked mounts (propagation can't be
    /// changed), which is a different and incompatible scenario.
    #[test]
    fn root_only_two_stage_pivot_fs_before_user_ns_succeeds() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let Some(rootfs_dir) = make_minimal_rootfs() else {
                    return 1;
                };
                let req = request_with_rootfs(&rootfs_dir);
                if unshare(&[Namespace::Mount]).is_err() {
                    return 2;
                }
                if req.pivot_fs().is_err() {
                    return 3;
                }
                if unshare(&[Namespace::User]).is_err() {
                    return 4;
                }
                0
            })
        });
    }

    /// Regression test: pivot_fs() called after entering the new user namespace
    /// fails with EPERM — the mount namespace is owned by the initial user namespace,
    /// not the new one, so mount operations require CAP_SYS_ADMIN in the wrong ns.
    ///
    /// Root-only: same reasoning as two_stage_pivot_fs_before_user_ns_succeeds.
    #[test]
    fn root_only_two_stage_pivot_fs_after_user_ns_fails() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let Some(rootfs_dir) = make_minimal_rootfs() else {
                    return 1;
                };
                let req = request_with_rootfs(&rootfs_dir);
                if unshare(&[Namespace::Mount]).is_err() {
                    return 1;
                }
                if unshare(&[Namespace::User]).is_err() {
                    return 1;
                }
                // pivot_fs after user ns must fail
                if req.pivot_fs().is_ok() { 1 } else { 0 }
            })
        });
    }

    /// Skip-two-stage path (skip_two_stage_userns=true): all namespaces unshared
    /// together atomically, so the user namespace owns the mount and pid namespaces
    /// from creation (mounts are not locked). The forked child (PID 1 in the new
    /// pid namespace) calls pivot_fs() and it must succeed.
    #[test]
    fn root_only_skip_two_stage_pivot_fs_succeeds() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let Some(rootfs_dir) = make_minimal_rootfs() else {
                    return 1;
                };
                let req = request_with_rootfs(&rootfs_dir);
                if unshare(&[Namespace::User, Namespace::Mount, Namespace::Pid]).is_err() {
                    return 2;
                }
                // Fork so the child enters the new pid namespace as PID 1.
                // proc mount in pivot_fs() requires being inside the owned pid namespace.
                let child = match fork() {
                    Ok(ForkResult::Child) => {
                        libc::_exit(if req.pivot_fs().is_err() { 1 } else { 0 })
                    }
                    Ok(ForkResult::Parent { child }) => child,
                    Err(_) => return 3,
                };
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => 0,
                    _ => 4,
                }
            })
        });
    }

    /// Mount-only namespace (no user namespace): pivot_fs() succeeds.
    /// Root-only: creating a mount namespace without any user namespace requires
    /// CAP_SYS_ADMIN in the initial user namespace.
    #[test]
    fn root_only_mount_only_ns_pivot_fs_succeeds() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let Some(rootfs_dir) = make_minimal_rootfs() else {
                    return 1;
                };
                let req = request_with_rootfs(&rootfs_dir);
                if unshare(&[Namespace::Mount]).is_err() {
                    return 2;
                }
                if req.pivot_fs().is_err() {
                    return 3;
                }
                0
            })
        });
    }

    #[test]
    fn root_only_apply_exec_prep_preserves_raised_cap_across_uid_change() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let exec = ExecutableSpec {
                    uid: Some(NOBODY_UID),
                    gid: Some(NOBODY_UID),
                    ..Default::default()
                };
                let caps = Capabilities {
                    raise: Some(vec!["CAP_NET_RAW".to_string()]),
                    raise_ambient: None,
                    drop: None,
                };
                if preexec_prep(&exec, Some(&caps)).is_err() {
                    return 1;
                }
                let Ok(now) = get_caps() else {
                    return 2;
                };
                if !CapabilityBit::NetRaw.get_from(now.permitted) {
                    return 3;
                }
                if !CapabilityBit::NetRaw.get_from(now.effective) {
                    return 4;
                }
                0
            })
        });
    }

    #[test]
    fn root_only_raise_then_setuid_without_keep_caps_drops_cap() {
        if !is_root() {
            return;
        }
        assert!(unsafe {
            in_child(|| {
                let caps = Capabilities {
                    raise: Some(vec!["CAP_NET_RAW".to_string()]),
                    raise_ambient: None,
                    drop: None,
                };
                if apply_capabilities(Some(&caps)).is_err() {
                    return 1;
                }
                let Ok(before) = get_caps() else {
                    return 2;
                };
                if !CapabilityBit::NetRaw.get_from(before.effective) {
                    return 3;
                }
                if apply_gid_uid(Some(NOBODY_UID), Some(NOBODY_UID), None).is_err() {
                    return 4;
                }
                let Ok(after) = get_caps() else {
                    return 5;
                };
                if CapabilityBit::NetRaw.get_from(after.permitted) {
                    return 6;
                }
                if CapabilityBit::NetRaw.get_from(after.effective) {
                    return 7;
                }
                0
            })
        });
    }
}
