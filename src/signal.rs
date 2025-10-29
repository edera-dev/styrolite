use anyhow::{Result, anyhow};
use log::debug;
use nix::sys::signal::{self, SigHandler, Signal};
use nix::unistd::Pid;
use std::sync::atomic::{AtomicI32, Ordering};

/// Set of signals forwarded from the parent to the child
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGHUP,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
];

/// Stored child pid used by the parent signal handler to forward signals
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// forward_signal loads the stored child pid and then kills the child with the
/// trapped signal.
extern "C" fn forward_signal(signum: i32) {
    let pid = CHILD_PID.load(Ordering::SeqCst);

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

/// store_child_pid stores a pid in the static variable which is used by the signal handler to
/// forward signals.
pub fn store_child_pid(pid: i32) {
    debug!("Registering child PID {pid} for signal forwarding");
    CHILD_PID.store(pid, Ordering::SeqCst);
}
