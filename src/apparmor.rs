//! AppArmor profile transition for the workload process.

use std::io::Write;

/// Stage an AppArmor profile transition that takes effect on the next `execve`
/// (the kernel's `aa_change_onexec` interface).
///
/// The named profile must already be loaded in the kernel. Writing an un-loaded/unknown
/// profile name here will cause the next `execve` to fail with `-ENOENT`.
/// Must be called after `PR_SET_NO_NEW_PRIVS` and before `execvpe()`.
///
/// The command must reach the kernel in a single `write(2)`, so it is formatted
/// into one buffer. Writes to the per-LSM attr node `/proc/self/attr/apparmor/exec`
/// (present on Linux 5.1+), and falls back to the pre-5.1 global node `/proc/self/attr/exec`.
pub fn change_onexec(profile: &str) -> std::io::Result<()> {
    let cmd = format!("exec {profile}");
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/attr/apparmor/exec")
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/attr/exec")?,
        Err(e) => return Err(e),
    };
    file.write_all(cmd.as_bytes())
}
