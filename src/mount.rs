use std::env;
use std::ffi::{CString, c_ulong};
use std::fs;
use std::ptr;

use anyhow::{Result, bail};
use libc;

use crate::config::{MountSpec, Mountable};

fn unpack(data: Option<String>) -> CString {
    if data.is_some()
        && let Ok(cstr) = CString::new(data.unwrap())
    {
        return cstr;
    }

    CString::new("").expect("")
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
        let fstype_p = if self.fstype.is_none() {
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

        if self.safe {
            flags |= libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        }

        if self.read_only {
            flags |= libc::MS_RDONLY;
        }

        unsafe {
            let result = libc::mount(source_p, target_p, fstype_p, flags, ptr::null());

            if result < 0 {
                bail!("unable to mount");
            }
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
