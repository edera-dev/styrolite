use crate::caps::CapabilityBit;
use crate::namespace::Namespace;
use anyhow::{Result, bail};
use libc::{gid_t, pid_t, uid_t};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AttachRequest {
    /// The PID to join in the namespace.
    pub pid: pid_t,
    
    /// The executable specification for the new process created in this
    /// container.
    pub exec: ExecutableSpec,
    
    /// An opaque string which is used to designate workload identity.
    /// In the case of attaching to a pre-existing container, it should be
    /// the UUID of the target container.
    /// If this is unset, then we will not correlate resource usage from
    /// the attached process with the rest of the resource usage of the
    /// container.
    pub workload_id: Option<String>,
    
    /// An optional path to a cgroup2 filesystem to attach to. See
    /// CreateRequest::cgroupfs for a more detailed explanation.
    pub cgroupfs: Option<String>,
    
    /// A set of namespaces to join.
    pub namespaces: Option<Vec<Namespace>>,
    /// Capabilities for this attachment.
    pub capabilities: Option<Capabilities>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct IdMapping {
    /// The base UID/GID inside the user namespace.
    pub base_nsid: u32,
    
    /// The base UID/GID outside the user namespace.
    pub base_hostid: u32,
    
    /// The number of UID/GIDs to remap.
    pub remap_count: u32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ExecutableSpec {
    /// Executable path (not resolved by PATH)
    pub executable: Option<String>,
    
    /// All arguments to the executable.
    pub arguments: Option<Vec<String>>,
    
    /// A working directory, assuming that the rootfs is /.
    pub working_directory: Option<String>,
    
    /// Environment variables, order kept by insertion.
    pub environment: Option<BTreeMap<String, String>>,
    
    /// An optional UID to assume.
    /// These UIDs are relative to the user namespace that is optionally set up.
    pub uid: Option<uid_t>,
    
    /// An optional GID to assume.
    /// These GIDs are relative to the user namespace that is optionally set up.
    pub gid: Option<gid_t>,
    
    /// An optional set of process-specific resource limits.
    /// If this set is not provided, setrlimit(2) will not be called.
    pub process_limits: Option<ProcessResourceLimits>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    /// An opaque string which is used to designate workload identity.
    /// Should typically be a UUID, however, if not set, the supervisor
    /// process ID will be used as a limited fallback.
    pub workload_id: Option<String>,
    
    /// A bare rootfs. It should be assumed the rootfs is writable via a read-only layer and a writeable backing layer.
    /// It should be assumed the rootfs might already have mounts.
    /// It should be assumed that the rootfs might already have proc, sys, and dev mounts. (This might need to change?)
    pub rootfs: Option<String>,
    
    /// The executable specification for the initial process created in this
    /// container.
    pub exec: ExecutableSpec,
    
    /// A set of UID mapping rules, used to set up the user namespace.
    /// If empty, a user namespace will not be created.
    pub uid_mappings: Option<Vec<IdMapping>>,
    
    /// A set of GID mapping rules, used to set up the user namespace.
    /// If empty, a user namespace will not be created.
    pub gid_mappings: Option<Vec<IdMapping>>,
    
    /// An optional set of mount specifications.
    /// `/proc` will be mounted regardless of whether a mount specification is configured.
    pub mounts: Option<Vec<MountSpec>>,
    
    /// An optional set of resource limits.
    /// If this set is not provided, no cgroups will be configured.
    pub limits: Option<ResourceLimits>,
    
    /// An optional path to a cgroup2 filesystem for setting resource limits.
    /// If this is not provided, we will attempt to set limits using the root
    /// hierarchy, but unprivileged users will require their own cgroup
    /// delegation. Ideally, this should be a path to that delegation.
    pub cgroupfs: Option<String>,
    
    /// An optional hostname to be used for the container.
    /// If this is not provided, the workload identity will be used.
    pub hostname: Option<String>,
    
    /// An optional list of mutations to apply to the container FS.
    pub mutations: Option<Vec<Mutation>>,
    
    /// A set of namespaces to join.
    pub namespaces: Option<Vec<Namespace>>,
    
    /// Whether setgroups(2) should be denied in this container.
    pub setgroups_deny: Option<bool>,
    /// Capabilities for this container.
    pub capabilities: Option<Capabilities>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    /// Capabilities to raise on the container.
    pub raise: Option<Vec<String>>,
    /// Ambient capabilities to raise on the container.
    pub raise_ambient: Option<Vec<String>>,
    /// Capabilities to drop on the container.
    pub drop: Option<Vec<String>>,
}

impl Capabilities {
    pub fn names_as_bits(names: &[String]) -> Result<Vec<CapabilityBit>> {
        let mut caps = HashSet::new();
        for name in names {
            let bit = CapabilityBit::from_str(name).ok();
            if let Some(bit) = bit {
                caps.insert(bit);
            } else if name.to_uppercase() == "ALL" {
                caps.extend(CapabilityBit::ALL.iter().cloned());
            } else {
                bail!("unknown capability: {}", name);
            }
        }
        Ok(caps.into_iter().collect())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Config {
    Create(CreateRequest),
    Attach(AttachRequest),
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CreateDirMutation {
    /// The directory inside the container FS to create.
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Mutation {
    CreateDir(CreateDirMutation),
}

pub trait Wrappable {
    /// Process a configuration request.
    fn wrap(&self) -> Result<()>;
}

pub trait Validatable {
    /// Validate the configuration and error if the configuration is invalid.
    fn validate(&self) -> Result<()>;
}

impl Validatable for CreateRequest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl Validatable for AttachRequest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

pub trait Configurable: Serialize + Validatable {
    fn encapsulate(self) -> Result<Config>;
}

impl Configurable for CreateRequest {
    fn encapsulate(self) -> Result<Config> {
        Ok(Config::Create(self))
    }
}

impl Configurable for AttachRequest {
    fn encapsulate(self) -> Result<Config> {
        Ok(Config::Attach(self))
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MountSpec {
    /// The source location or device node for a mount point.
    pub source: Option<String>,

    /// The target location of the mount point.
    pub target: String,

    /// The filesystem of the mount point.
    pub fstype: Option<String>,

    /// Whether the mount point is a bind mount.
    pub bind: bool,

    /// Whether the mount point should recurse.
    pub recurse: bool,

    /// Whether the mount point should be unshared, e.g. MS_PRIVATE flag.
    pub unshare: bool,

    /// Whether the mount point should be mounted with safety options, e.g. MS_NOSUID.
    pub safe: bool,

    /// Whether the target mount point should be created as a directory if it
    /// does not exist.
    pub create_mountpoint: bool,
}

pub trait Mountable {
    /// Perform the mount operation.
    fn mount(&self) -> Result<()>;

    /// Pivot, making this mount point the new rootfs.
    /// The old rootfs is unmounted as a side effect.
    fn pivot(&self) -> Result<()>;
}

pub type ResourceLimits = BTreeMap<String, String>;

pub trait Mutatable {
    fn mutate(&self, rootfs: &str) -> Result<()>;
}

/// Resource limits for processes inside the container itself.
/// If a value is not set, the resource limit will be disabled by setting it
/// to unlimited.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ProcessResourceLimits {
    /// The maximum size in bytes for container processes to use as virtual address
    /// space.  See RLIMIT_AS in setrlimit(2) for more detail.
    pub address_space_size: Option<u64>,

    /// The maximum size in bytes for any core file created when a container process
    /// terminates from crashing.  See RLIMIT_CORE in setrlimit(2) for more detail.
    pub core_size: Option<u64>,

    /// The maximum amount of CPU seconds a process can consume before a process is
    /// terminated.  See RLIMIT_CPU in setrlimit(2) for more detail.
    pub cpu_time: Option<u64>,

    /// The maximum amount of heap memory that a process can consume before further
    /// heap allocations fail.  See RLIMIT_DATA in setrlimit(2) for more detail.
    pub data_space_size: Option<u64>,

    /// The maximum amount of written bytes to disk that a process can write before
    /// further writes fail.  See RLIMIT_FSIZE in setrlimit(2) for more detail.
    pub file_size: Option<u64>,

    /// The maximum amount, in bytes, of memory pages which can be locked by a process.
    /// This value is rounded down to the nearest page size boundary.
    /// See RLIMIT_MEMLOCK in setrlimit(2) for more detail.
    pub locked_space_size: Option<u64>,

    /// The maximum amount, in bytes, of memory pages which can be allocated for POSIX
    /// message queues.  The value is rounded down to the nearest page size boundary.
    /// See RLIMIT_MSGQUEUE in setrlimit(2) for more detail.
    pub msgqueue_size: Option<u64>,

    /// The maximum niceness level ceiling for a given process.  The calculated value
    /// inside the kernel starts at 20 and is subtracted by the supplied ceiling value.
    /// See RLIMIT_NICE in setrlimit(2) for more detail.
    pub nice_ceiling: Option<u64>,

    /// The maximum number of open file descriptors for processes inside the container.
    /// See RLIMIT_NOFILE in setrlimit(2) for more detail.
    pub open_files: Option<u64>,

    /// The maximum number of threads/LWPs which can be a child of a given process.
    /// See RLIMIT_NPROC in setrlimit(2) for more detail.
    pub thread_limit: Option<u64>,

    /// The maximum amount of resident memory allowed for a given process.
    /// See RLIMIT_RSS in setrlimit(2) for more detail.
    pub resident_space_size: Option<u64>,

    /// The maximum realtime niceness level ceiling for a given process.
    /// See RLIMIT_RTPRIO in setrlimit(2) for more detail.
    pub real_time_priority: Option<u64>,

    /// The maximum amount of CPU microseconds a process may spend before making
    /// a blocking syscall or otherwise being preempted by the kernel scheduler.
    /// See RLIMIT_RTTIME in setrlimit(2) for more detail.
    pub real_time_limit: Option<u64>,

    /// The maximum number of pending signals that can be delivered to a process
    /// at any time.  See RLIMIT_SIGPENDING in setrlimit(2) for more detail.
    pub pending_signal_limit: Option<u64>,

    /// The stack size that should be used for the main thread's stack when creating
    /// new processes.  On Linux, this normally defaults to 8MB, although the stack
    /// size of other threads is dependent on the system's C library: GLIBC defaults
    /// to an 8MB limit for secondary threads, while musl defaults to 80KB unless a
    /// different stack size annotation is present on the binary being run.
    /// See RLIMIT_STACK in setrlimit(2) for more detail.
    pub main_thread_stack_size: Option<u64>,
}
