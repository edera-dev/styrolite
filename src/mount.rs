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

pub fn mount_setattr_fd(fd: &OwnedFd, recursive: bool, attr: &libc::mount_attr) -> io::Result<()> {
    let mut flags = libc::AT_EMPTY_PATH as c_uint;
    if recursive {
        flags |= libc::AT_RECURSIVE as c_uint;
    }

    mount_setattr(fd.as_raw_fd(), "", flags, attr)
}

/// Join a container-absolute `path` under `rootfs`, avoiding a doubled
/// separator. `path` is treated as rooted at the container's `/`.
fn join_rootfs(rootfs: &str, path: &str) -> String {
    format!(
        "{}/{}",
        rootfs.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// Mask a single container path (OCI `maskedPaths` semantics): cover a file
/// target with a bind of `/dev/null` (reads return EOF, writes are discarded)
/// and a directory target with an empty read-only tmpfs. `path` is resolved
/// under `rootfs`. A target that does not exist is skipped -- the default mask
/// set is a superset that not every rootfs/kernel populates.
///
/// Must be called before pivot, while the original `/dev/null` is still
/// reachable at its normal path.
pub fn mask_path(rootfs: &str, path: &str) -> Result<()> {
    let target = join_rootfs(rootfs, path);
    let meta = match fs::symlink_metadata(&target) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("stat {target}: {e}")),
    };

    let spec = if meta.is_dir() {
        // Empty read-only tmpfs over the directory (nosuid/nodev/noexec).
        MountSpec {
            source: Some("tmpfs".to_string()),
            target,
            fstype: Some("tmpfs".to_string()),
            bind: false,
            recurse: false,
            unshare: false,
            safe: true,
            create_mountpoint: false,
            read_only: true,
            data: Some("size=0k".to_string()),
        }
    } else {
        // Bind /dev/null over the file. Not marked read-only or `safe`: the
        // mask is the bind to /dev/null itself, and MOUNT_ATTR_NODEV would
        // stop it from behaving as the device node it now is.
        MountSpec {
            source: Some("/dev/null".to_string()),
            target,
            fstype: None,
            bind: true,
            recurse: false,
            unshare: false,
            safe: false,
            create_mountpoint: false,
            read_only: false,
            data: None,
        }
    };

    spec.mount()
}

/// Make a single container path read-only (OCI `readonlyPaths` semantics)
/// while leaving its contents readable: bind the target onto itself and
/// recursively remount read-only. `path` is resolved under `rootfs`; a target
/// that does not exist is skipped.
pub fn make_readonly(rootfs: &str, path: &str) -> Result<()> {
    let target = join_rootfs(rootfs, path);
    match fs::symlink_metadata(&target) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("stat {target}: {e}")),
    }

    let spec = MountSpec {
        source: Some(target.clone()),
        target,
        fstype: Some("none".to_string()),
        bind: true,
        recurse: true,
        unshare: false,
        safe: false,
        create_mountpoint: false,
        read_only: true,
        data: None,
    };

    spec.mount()
}

impl Mountable for MountSpec {
    fn seal(&self) -> Result<()> {
        let tree = open_tree(
            libc::AT_FDCWD,
            self.source
                .as_deref()
                .ok_or_else(|| anyhow!("source missing"))?,
            libc::OPEN_TREE_CLOEXEC,
        )?;

        let mut attr: libc::mount_attr = unsafe { std::mem::zeroed() };
        attr.attr_set |= libc::MOUNT_ATTR_RDONLY;
        mount_setattr_fd(&tree, false, &attr)?;

        Ok(())
    }

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
            let source_is_file = self.bind
                && self
                    .source
                    .as_deref()
                    .and_then(|s| std::path::Path::new(s).metadata().ok())
                    .map(|m| !m.is_dir())
                    .unwrap_or(false);

            if source_is_file {
                if let Some(parent) = std::path::Path::new(&self.target).parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::File::create(&self.target)?;
            } else {
                fs::create_dir_all(&self.target)?;
            }
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

        let data_cstr = self
            .data
            .as_ref()
            .map(|d| CString::new(d.as_str()).unwrap());
        let data_ptr = data_cstr
            .as_ref()
            .map(|c| c.as_ptr() as *const libc::c_void)
            .unwrap_or(ptr::null());

        unsafe {
            let rc = libc::mount(source_p, target_p, fstype_p, flags, data_ptr);
            if rc < 0 {
                let err = io::Error::last_os_error();
                bail!(
                    "unable to mount: source={:?} target={:?} fstype={:?} bind={} flags=0x{:x}: {}",
                    self.source,
                    self.target,
                    self.fstype,
                    self.bind,
                    flags,
                    err
                );
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

            mount_setattr(libc::AT_FDCWD, &self.target, msaflags, &attr).map_err(|e| anyhow!(e))?;
        }

        Ok(())
    }

    fn pivot(&self) -> Result<()> {
        let dot = CString::from(c".");
        let dot_p = dot.as_ptr();

        env::set_current_dir(self.target.clone())?;

        unsafe {
            if libc::syscall(libc::SYS_pivot_root, dot_p, dot_p) < 0 {
                bail!("failed to pivot_root: {}", io::Error::last_os_error());
            }

            if libc::umount2(dot_p, libc::MNT_DETACH) < 0 {
                bail!("failed to unmount old root: {}", io::Error::last_os_error());
            }
        }

        env::set_current_dir("/")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::join_rootfs;

    #[test]
    fn join_rootfs_avoids_double_separators() {
        assert_eq!(
            join_rootfs("/run/root", "/proc/kcore"),
            "/run/root/proc/kcore"
        );
        // Trailing slash on rootfs and missing leading slash on path.
        assert_eq!(join_rootfs("/run/root/", "proc/sys"), "/run/root/proc/sys");
        // rootfs of "/" stays single-separator.
        assert_eq!(
            join_rootfs("/", "/proc/sysrq-trigger"),
            "/proc/sysrq-trigger"
        );
    }
}
