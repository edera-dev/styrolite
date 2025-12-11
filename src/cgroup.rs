//! Control Groups v2 support.
//!
//! We use cgroup2 to enforce resource limits against a workload,
//! by writing appropriate values to the cgroup. Control Groups
//! v1 is not supported at all.
//!
//! We also support the use of delegated cgroups, though it requires
//! some additional configuration, and the delegated root must be
//! set up ahead of time.
//!
//! To create a new delegated root, the root user must:
//! - make a subtree in /sys/fs/cgroup
//! - recursively chown that subtree to the delegated user
//! - enable the controllers that the delegated user may have
//!   access to.
//!
//! In other words, in a shell we would do for example:
//!
//! ```sh
//! % mkdir /sys/fs/cgroup/styrolite-1000
//! % chown -R 1000:1000 /sys/fs/cgroup/styrolite-1000
//! % echo "+memory +cpu" > /sys/fs/cgroup/styrolite-1000/cgroup.subtree_control
//! ```
//!
//! From there, our hypothetical user with UID 1000 could create
//! their own control groups:
//!
//! ```sh
//! $ mkdir /sys/fs/cgroup/styrolite-1000/a
//! $ echo 100M > /sys/fs/cgroup/styrolite-1000/a/memory.max
//! ```
//!
//! Then we can bind a PID to the cgroup:
//!
//! ```sh
//! $ echo 12345 >> /sys/fs/cgroup/styrolite-1000/a/cgroup.procs
//! ```
//!
//! In styrolite, we move the supervisor (styrolite-bin) into the
//! configured cgroup.  This is because it allows us to guarantee
//! that supervised processes automatically get spawned into the
//! correct cgroup without any race conditions.

use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Error, Result, bail};
use libc::{AT_EACCESS, AT_FDCWD, F_OK, c_char, faccessat};

#[derive(Clone, Debug)]
pub struct CGroup {
    /// The root (or delegated root) of the cgroup2 tree.
    root: String,
}

impl CGroup {
    /// Open a CGroup walker at a given root.
    pub fn open(root: &str) -> Result<CGroup> {
        let path = CString::new(root.as_bytes())?;

        unsafe {
            let ret = faccessat(AT_FDCWD, path.as_ptr() as *const c_char, F_OK, AT_EACCESS);
            if ret != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        };

        Ok(CGroup {
            root: root.to_string(),
        })
    }

    /// Open a CGroup walker at a given child node.
    pub fn open_child<P: AsRef<Path>>(self, child: P) -> Result<CGroup> {
        let mut path = PathBuf::from(self.root);
        path.push(child);

        let finalpath = match path.to_str() {
            Some(fp) => fp,
            None => {
                bail!("generated cgroupfs path is invalid UTF-8");
            }
        };

        CGroup::open(finalpath)
    }

    /// Create a child hierarchy and open it.
    pub fn create_child<P: AsRef<Path>>(self, child: P) -> Result<CGroup> {
        let mut path = PathBuf::from(self.root);
        path.push(child);

        let finalpath = match path.to_str() {
            Some(fp) => fp,
            None => {
                bail!("generated cgroupfs path is invalid UTF-8");
            }
        };

        fs::create_dir_all(finalpath)?;
        CGroup::open(finalpath)
    }

    /// Set child node at the present root.
    pub fn set_child_value<P: AsRef<Path>>(self, child: P, value: &str) -> Result<()> {
        let mut path = PathBuf::from(self.root);
        path.push(child);

        let finalpath = match path.to_str() {
            Some(fp) => fp,
            None => {
                bail!("generated cgroupfs path is invalid UTF-8");
            }
        };

        fs::write(finalpath, value).map_err(Error::from)
    }
}
