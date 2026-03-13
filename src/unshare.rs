use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::Result;
use libc;

use crate::namespace::{Namespace, to_clone_flags};

/// Fork the current process namespace set into a new set of namespaces.
pub fn unshare<'x>(iter: impl IntoIterator<Item = &'x Namespace>) -> Result<()> {
    let flags = iter.into_iter().fold(0, |acc, x| acc | to_clone_flags(*x));

    unsafe {
        if libc::unshare(flags) < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}

/// A simple wrapper around the pidfd_open(2) syscall.
pub fn pidfd_open(target_pid: libc::pid_t) -> Result<OwnedFd> {
    let flags: libc::c_uint = 0;

    unsafe {
        let result = libc::syscall(libc::SYS_pidfd_open, target_pid, flags);

        if result < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(OwnedFd::from_raw_fd(result as libc::c_int))
        }
    }
}

/// Attach to a pre-existing set of namespaces.
/// For security reasons, this only works on kernels new enough to support
/// process descriptors (so-called PID FDs) as the old way of using setns(2)
/// with namespace FDs imposes a race condition.
pub fn setns<'x>(
    target_pid: libc::pid_t,
    iter: impl IntoIterator<Item = &'x Namespace>,
) -> Result<()> {
    let flags = iter.into_iter().fold(0, |acc, x| acc | to_clone_flags(*x));
    let pid_fd = pidfd_open(target_pid)?;

    unsafe {
        if libc::setns(pid_fd.as_raw_fd(), flags) < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}
