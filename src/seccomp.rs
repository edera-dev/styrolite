/// A seccomp-bpf filter program.
///
/// The caller builds the BPF program as a list of (code, jt, jf, k)
/// instructions. Styrolite installs it via `seccomp(2)` after
/// capabilities are set but before `execvpe()`.
///
/// Requires `no_new_privs = true` on the `ExecutableSpec`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SeccompFilter {
    /// BPF instructions as (code, jt, jf, k) tuples.
    pub instructions: Vec<(u16, u8, u8, u32)>,
}

impl SeccompFilter {
    /// Install the seccomp filter via `seccomp(2)` with `SECCOMP_FILTER_FLAG_TSYNC`.
    ///
    /// Uses `seccomp(2)` instead of `prctl(PR_SET_SECCOMP)` to synchronize the
    /// filter across all threads via `SECCOMP_FILTER_FLAG_TSYNC`.
    ///
    /// # Safety
    ///
    /// Must be called after `prctl(PR_SET_NO_NEW_PRIVS, 1)` and before `execvpe()`.
    /// The caller must ensure the BPF program is valid.
    pub unsafe fn install(&self) -> std::io::Result<()> {
        let filters: Vec<libc::sock_filter> = self
            .instructions
            .iter()
            .map(|&(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
            .collect();
        let prog = libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_ptr() as *mut _,
        };

        // Use seccomp(2) with TSYNC to synchronize filter across all threads.
        // SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1
        let ret = libc::syscall(
            libc::SYS_seccomp,
            1u64, // SECCOMP_SET_MODE_FILTER
            1u64, // SECCOMP_FILTER_FLAG_TSYNC
            &prog as *const _,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
