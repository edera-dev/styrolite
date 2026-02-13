use std::env;
use std::ffi::{CString, c_ulong};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_int, c_uint};
use std::ptr;

use anyhow::{Result, anyhow, bail};
use libc;

use crate::config::{MountSpec, Mountable};

const MOVE_MOUNT_F_EMPTY_PATH: c_uint = 0x4;

/// open_tree(2)
pub fn open_tree(dfd: c_int, path: &str, flags: c_uint) -> io::Result<OwnedFd> {
    let c_path = CString::new(path)?;
    let ret = unsafe { libc::syscall(libc::SYS_open_tree, dfd, c_path.as_ptr(), flags) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret as c_int) })
}

/// move_mount(2)
pub fn move_mount(
    from_dfd: c_int,
    from_path: &str,
    to_dfd: c_int,
    to_path: &str,
    flags: c_uint,
) -> io::Result<()> {
    let c_from = CString::new(from_path)?;
    let c_to = CString::new(to_path)?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from_dfd,
            c_from.as_ptr(),
            to_dfd,
            c_to.as_ptr(),
            flags,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// mount_setattr(2)
pub fn mount_setattr(
    dfd: c_int,
    path: &str,
    flags: c_uint,
    attr: &libc::mount_attr,
) -> io::Result<()> {
    let c_path = CString::new(path)?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            dfd,
            c_path.as_ptr(),
            flags,
            attr as *const libc::mount_attr,
            std::mem::size_of::<libc::mount_attr>(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn unpack(data: Option<String>) -> CString {
    if data.is_some()
        && let Ok(cstr) = CString::new(data.unwrap())
    {
        return cstr;
    }

    CString::new("").expect("")
}

pub fn move_mount_fd_to(fd: &OwnedFd, target: &str) -> io::Result<()> {
    move_mount(
        fd.as_raw_fd(),
        "",
        libc::AT_FDCWD,
        target,
        MOVE_MOUNT_F_EMPTY_PATH as c_uint,
    )
}

pub fn mount_setattr_fd(
    fd: &OwnedFd,
    recursive: bool,
    attr: &libc::mount_attr,
) -> io::Result<()> {
    let mut flags = libc::AT_EMPTY_PATH as c_uint;
    if recursive {
        flags |= libc::AT_RECURSIVE as c_uint;
    }

    mount_setattr(fd.as_raw_fd(), "", flags, attr)
}

impl Mountable for MountSpec {
    fn mount(&self) -> Result<()> {
        let source = unpack(self.source.clone());
        let source_p = if self.source.is_none() {
            ptr::null()
        } else {
            source.as_ptr()
        };

        let fstype = unpack(self.fstype.clone());
        let fstype_p = if self.fstype.is_none() || self.bind {
            ptr::null()
        } else {
            fstype.as_ptr()
        };

        let target = CString::new(self.target.clone())?;
        let target_p = target.as_ptr();

        if self.create_mountpoint {
            fs::create_dir_all(self.target.clone())?;
        }

        let mut flags: c_ulong = libc::MS_SILENT;

        if self.bind {
            flags |= libc::MS_BIND;
        }

        if self.unshare {
            flags |= libc::MS_PRIVATE;
        }

        if self.recurse {
            flags |= libc::MS_REC;
        }

        unsafe {
            let rc = libc::mount(source_p, target_p, fstype_p, flags, ptr::null());
            if rc < 0 {
                bail!("unable to mount");
            }
        }

        let mut set: c_ulong = 0;

        if self.safe {
            set |= libc::MOUNT_ATTR_NOSUID as c_ulong;
            set |= libc::MOUNT_ATTR_NODEV as c_ulong;
            set |= libc::MOUNT_ATTR_NOEXEC as c_ulong;
        }

        if self.read_only {
            set |= libc::MOUNT_ATTR_RDONLY as c_ulong;
        }

        if set != 0 {
            let mut attr: libc::mount_attr = unsafe { std::mem::zeroed() };
            attr.attr_set = set as u64;
            attr.attr_clr = 0;
            attr.propagation = 0;
            attr.userns_fd = 0;

            let mut msaflags: c_uint = 0;
            if self.recurse {
                msaflags |= libc::AT_RECURSIVE as c_uint;
            }

            mount_setattr(libc::AT_FDCWD, &self.target, msaflags, &attr)
                .map_err(|e| anyhow!(e))?;
        }

        Ok(())
    }

    fn pivot(&self) -> Result<()> {
        let dot = CString::from(c".");
        let dot_p = dot.as_ptr();

        env::set_current_dir(self.target.clone())?;

        unsafe {
            if libc::syscall(libc::SYS_pivot_root, dot_p, dot_p) < 0 {
                bail!("unable to pivot root");
            }

            if libc::umount2(dot_p, libc::MNT_DETACH) < 0 {
                bail!("unable to unmount old root");
            }
        }

        env::set_current_dir("/")?;

        Ok(())
    }
}
