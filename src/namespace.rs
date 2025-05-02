use std::ffi::c_int;

use serde::{Deserialize, Serialize};

/// Unshare the time namespace, so that the calling process has a new time
/// namespace for its children which is not shared with any previously existing
/// process. The calling process is _not_ moved into the new namespace.
///
/// Use of `CLONE_NEWTIME` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWTIME: c_int = 0x00000080;

/// Unshare the mount namespace, so that the calling process has a private copy
/// of its namespace which is not shared with any other process. Specifying
/// this flag automatically implies `CLONE_FS` as well.
///
/// Use of `CLONE_NEWNS` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWNS: c_int = 0x00020000;

/// Unshare the cgroup namespace.
///
/// Use of `CLONE_NEWCGROUP` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWCGROUP: c_int = 0x02000000;

/// Unshare the UTS IPC namespace, so that the calling process has a private
/// copy of the UTS namespace which is not shared with any other process.
///
/// Use of `CLONE_NEWUTS` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWUTS: c_int = 0x04000000;

/// Unshare the IPC namespace, so that the calling process has a private copy
/// of the IPC namespace which is not shared with any other process.
///
/// Use of `CLONE_NEWIPC` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWIPC: c_int = 0x08000000;

/// Unshare the user namespace, so that the calling process is moved into a new
/// user namespace which is not shared with any previously existing process.
/// The caller obtains a full set of capabilities in the new namespace.
///
/// `CLONE_NEWUSER` requires that the calling process is not threaded;
/// specifying `CLONE_NEWUSER` automatically implies `CLONE_THREAD`. Since
/// Linux 3.9, `CLONE_NEWUSER` also automatically implies `CLONE_FS`.
///
/// `CLONE_NEWUSER` requires that the user ID and group ID of the calling
/// process are mapped to user IDs and group IDs in the user namespace of the
/// calling process at the time of the call.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWUSER: c_int = 0x10000000;

/// Unshare the PID namespace, so that the calling process has a new PID
/// namespace for its children which is not shared with any previously existing
/// process.
///
/// The calling process is _not_ moved into the new namespace. The first child
/// created by the calling process will have the process ID 1 and will assume
/// the role of init(1) in the new namespace.
///
/// `CLONE_PID` automatically implies `CLONE_THREAD` as well.
///
/// Use of `CLONE_NEWPID` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWPID: c_int = 0x20000000;

/// Unshare the network namespace, so that the calling process is moved into a
/// new network namespace which is not shared with any previously existing
/// process.
///
/// Use of `CLONE_NEWNET` requires the `CAP_SYS_ADMIN` capability.
///
/// See: <https://man7.org/linux/man-pages/man2/unshare.2.html>
pub const CLONE_NEWNET: c_int = 0x40000000;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Namespace {
    /// See [`CLONE_NEWNS`].
    Mount,

    /// See [`CLONE_NEWUTS`].
    Uts,

    /// See [`CLONE_NEWIPC`].
    Ipc,

    /// See [`CLONE_NEWUSER`].
    User,

    /// See [`CLONE_NEWPID`].
    Pid,

    /// See [`CLONE_NEWNET`].
    Net,

    /// See [`CLONE_NEWCGROUP`].
    Cgroup,

    /// See [`CLONE_NEWTIME`].
    Time,
}

pub fn to_clone_flags(ns: Namespace) -> c_int {
    match ns {
        Namespace::Mount => CLONE_NEWNS,
        Namespace::Uts => CLONE_NEWUTS,
        Namespace::Ipc => CLONE_NEWIPC,
        Namespace::User => CLONE_NEWUSER,
        Namespace::Pid => CLONE_NEWPID,
        Namespace::Net => CLONE_NEWNET,
        Namespace::Cgroup => CLONE_NEWCGROUP,
        Namespace::Time => CLONE_NEWTIME,
    }
}
