use anyhow::{Result, anyhow};
use log::debug;
use nix::sys::signal::{self, SigHandler, Signal};
use nix::unistd::Pid;

/// Set of signals forwarded from the parent to the child
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGHUP,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
];

/// Stored child pid used by the parent signal handler to forward signals.
/// Styrolite is single threaded so this is safe to access.
static mut CHILD_PID: i32 = 0;

/// forward_signal loads the stored child pid and then kills the child with the
/// trapped signal.
extern "C" fn forward_signal(signum: i32) {
    let pid = unsafe { CHILD_PID };

    if pid <= 0 {
        return;
    }

    let pid = Pid::from_raw(pid);

    if let Ok(sig) = Signal::try_from(signum) {
        let _ = signal::kill(pid, sig);
    }
}

/// setup_parent_signal_handlers sets up signal forwarding in parent process
///
/// # Safety
///
/// This function uses nix::sys::signal::signal to set a SigHandler. The same
/// safety considerations apply.
pub unsafe fn setup_parent_signal_handlers() -> Result<()> {
    for &sig in FORWARDED_SIGNALS {
        debug!("Parent forwarding signal handler installed for {}", &sig);
        unsafe {
            signal::signal(sig, SigHandler::Handler(forward_signal))
                .map_err(|e| anyhow!("Failed to set signal handler for {:?}: {}", sig, e))?;
        }
    }
    Ok(())
}

/// reset_child_signal_handlers resets all the signal handlers for the given signals to their
/// default handlers.
///
/// # Safety
///
/// This function uses nix::sys::signal::signal to set a SigHandler. The same
/// safety considerations apply.
pub unsafe fn reset_child_signal_handlers() -> Result<()> {
    // Reset all signal handlers to default handler
    for &sig in FORWARDED_SIGNALS {
        debug!("Child resetting signal handler to default for {}", &sig);
        unsafe {
            signal::signal(sig, SigHandler::SigDfl)
                .map_err(|e| anyhow!("Failed to reset signal handler for {:?}: {}", sig, e))?;
        }
    }

    Ok(())
}

/// reset_sigpipe restores the SIGPIPE disposition to its default (SIG_DFL)
/// before handing off to the workload via execve.
///
/// The Rust runtime installs SIG_IGN for SIGPIPE at startup, and that
/// disposition is inherited across execve. Left ignored, workloads that expect
/// the default behaviour (e.g. shell pipelines terminating on a broken pipe)
/// wedge instead of being killed by SIGPIPE. runc and crun reset SIGPIPE to
/// SIG_DFL before exec for the same reason.
pub fn reset_sigpipe() -> Result<()> {
    debug!("Resetting SIGPIPE to default handler before exec");
    unsafe {
        signal::signal(Signal::SIGPIPE, SigHandler::SigDfl)
            .map_err(|e| anyhow!("Failed to reset SIGPIPE handler: {}", e))?;
    }
    Ok(())
}

/// store_child_pid stores a pid in the static variable which is used by the signal handler to
/// forward signals.
pub fn store_child_pid(pid: i32) {
    debug!("Registering child PID {pid} for signal forwarding");
    unsafe { CHILD_PID = pid }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// reset_sigpipe must restore SIGPIPE to SIG_DFL even when it starts out
    /// ignored (as the Rust runtime leaves it at startup), so workloads exec'd
    /// by styrolite see the standard broken-pipe behaviour.
    ///
    /// Signal dispositions are process-global; this test seeds and then
    /// restores SIGPIPE so it does not perturb other tests in the process.
    #[test]
    fn test_reset_sigpipe_restores_default() {
        // Seed the ignored disposition that the Rust runtime installs, and
        // remember whatever the process started with so we can restore it.
        let original = unsafe { signal::signal(Signal::SIGPIPE, SigHandler::SigIgn) }
            .expect("failed to seed SIGPIPE with SIG_IGN");

        reset_sigpipe().expect("reset_sigpipe failed");

        // signal() returns the previous disposition, so this both reads back
        // the state left by reset_sigpipe() and is idempotent (SIG_DFL again).
        let after = unsafe { signal::signal(Signal::SIGPIPE, SigHandler::SigDfl) }
            .expect("failed to read back SIGPIPE disposition");
        assert!(
            matches!(after, SigHandler::SigDfl),
            "SIGPIPE should be SIG_DFL after reset_sigpipe(), got {after:?}"
        );

        // Restore the disposition the test process started with.
        unsafe { signal::signal(Signal::SIGPIPE, original) }
            .expect("failed to restore original SIGPIPE disposition");
    }
}
