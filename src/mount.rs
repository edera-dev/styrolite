use std::env;
use std::ffi::{CString, c_ulong};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_int, c_uint};
use std::os::unix::fs::OpenOptionsExt;
use std::ptr;

use anyhow::{Result, anyhow, bail};
use libc;

use crate::config::{MountSpec, Mountable};

const MOVE_MOUNT_F_EMPTY_PATH: c_uint = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: c_uint = 0x40;

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

/// Open a container-absolute `path` as an `O_PATH` descriptor, resolving it and
/// every symlink along it with `rootfs` as `/`, so an absolute symlink in the
/// rootfs cannot lead outside it.
fn open_in_rootfs(rootfs: &str, path: &str) -> io::Result<fs::File> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(rootfs)?;
    let c_path = CString::new(path)?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            c_path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { fs::File::from_raw_fd(ret as c_int) })
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
    let target = match open_in_rootfs(rootfs, path) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("resolve {path} under {rootfs}: {e}")),
    };
    let meta = target.metadata().map_err(|e| anyhow!("stat {path}: {e}"))?;

    if meta.is_dir() {
        // Empty read-only tmpfs over the directory (nosuid/nodev/noexec).
        // mount(2) takes no target descriptor, so it reaches the resolved
        // directory through procfs.
        let target_path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))?;
        let rc = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target_path.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_SILENT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                c"size=0k".as_ptr() as *const libc::c_void,
            )
        };
        if rc < 0 {
            bail!("mount tmpfs over {path}: {}", io::Error::last_os_error());
        }
    } else {
        // Bind /dev/null over the file, with no mount attributes: the mask is
        // the bind to /dev/null itself, and MOUNT_ATTR_NODEV would stop it
        // from behaving as the device node it now is.
        let null = open_tree(
            libc::AT_FDCWD,
            "/dev/null",
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
        .map_err(|e| anyhow!("clone /dev/null: {e}"))?;
        move_mount(
            null.as_raw_fd(),
            "",
            target.as_raw_fd(),
            "",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
        .map_err(|e| anyhow!("bind /dev/null over {path}: {e}"))?;
    }

    Ok(())
}

/// Make a single container path read-only (OCI `readonlyPaths` semantics)
/// while leaving its contents readable: bind the target onto itself and
/// recursively remount read-only. `path` is resolved under `rootfs`; a target
/// that does not exist is skipped.
pub fn make_readonly(rootfs: &str, path: &str) -> Result<()> {
    let target = match open_in_rootfs(rootfs, path) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("resolve {path} under {rootfs}: {e}")),
    };

    let tree = open_tree(
        target.as_raw_fd(),
        "",
        libc::OPEN_TREE_CLONE
            | libc::OPEN_TREE_CLOEXEC
            | libc::AT_RECURSIVE as c_uint
            | libc::AT_EMPTY_PATH as c_uint,
    )
    .map_err(|e| anyhow!("clone the mount at {path}: {e}"))?;

    let mut attr: libc::mount_attr = unsafe { std::mem::zeroed() };
    attr.attr_set = libc::MOUNT_ATTR_RDONLY;
    mount_setattr_fd(&tree, true, &attr).map_err(|e| anyhow!("make {path} read-only: {e}"))?;

    move_mount(
        tree.as_raw_fd(),
        "",
        target.as_raw_fd(),
        "",
        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|e| anyhow!("bind {path} read-only over itself: {e}"))?;

    Ok(())
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
            .map(|d| {
                CString::new(d.as_str()).map_err(|e| {
                    anyhow!(
                        "mount data '{d}' for {} contains an interior NUL byte: {e}",
                        self.target
                    )
                })
            })
            .transpose()?;
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
    use super::open_in_rootfs;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn an_absolute_symlink_resolves_inside_the_rootfs() {
        let rootfs = tempfile::tempdir().unwrap();
        fs::create_dir_all(rootfs.path().join("usr/bin")).unwrap();
        fs::write(rootfs.path().join("usr/bin/ls"), "").unwrap();
        symlink("/usr/bin", rootfs.path().join("bin")).unwrap();

        let resolved = open_in_rootfs(rootfs.path().to_str().unwrap(), "/bin/ls")
            .unwrap()
            .metadata()
            .unwrap();
        let inside = fs::metadata(rootfs.path().join("usr/bin/ls")).unwrap();
        assert_eq!(
            (resolved.dev(), resolved.ino()),
            (inside.dev(), inside.ino())
        );
    }

    #[test]
    fn a_path_outside_the_rootfs_is_not_found() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "").unwrap();
        let rootfs = tempfile::tempdir().unwrap();
        symlink(outside.path(), rootfs.path().join("abs")).unwrap();
        symlink("../../../../../../../..", rootfs.path().join("up")).unwrap();
        let rootfs = rootfs.path().to_str().unwrap();

        for path in [
            "/abs/secret".to_string(),
            format!("/up{}/secret", outside.path().display()),
        ] {
            assert_eq!(
                open_in_rootfs(rootfs, &path).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "{path}"
            );
        }
    }
}
