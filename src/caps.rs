/* from <linux/capability.h> */
use anyhow::{Error, anyhow};
use libc::syscall;
use log::debug;
use std::io;
use std::str::FromStr;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityBit {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawIO = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
    Perfmon = 38,
    Bpf = 39,
    CheckpointRestore = 40,
}

pub struct CapabilityState {
    pub permitted: Vec<CapabilityBit>,
    pub effective: Vec<CapabilityBit>,
    pub inheritable: Vec<CapabilityBit>,
}

impl CapabilityBit {
    pub const ALL: &'static [CapabilityBit] = &[
        CapabilityBit::Chown,
        CapabilityBit::DacOverride,
        CapabilityBit::DacReadSearch,
        CapabilityBit::Fowner,
        CapabilityBit::Fsetid,
        CapabilityBit::Kill,
        CapabilityBit::Setgid,
        CapabilityBit::Setuid,
        CapabilityBit::Setpcap,
        CapabilityBit::LinuxImmutable,
        CapabilityBit::NetBindService,
        CapabilityBit::NetBroadcast,
        CapabilityBit::NetAdmin,
        CapabilityBit::NetRaw,
        CapabilityBit::IpcLock,
        CapabilityBit::IpcOwner,
        CapabilityBit::SysModule,
        CapabilityBit::SysRawIO,
        CapabilityBit::SysChroot,
        CapabilityBit::SysPtrace,
        CapabilityBit::SysPacct,
        CapabilityBit::SysAdmin,
        CapabilityBit::SysBoot,
        CapabilityBit::SysNice,
        CapabilityBit::SysResource,
        CapabilityBit::SysTime,
        CapabilityBit::SysTtyConfig,
        CapabilityBit::Mknod,
        CapabilityBit::Lease,
        CapabilityBit::AuditWrite,
        CapabilityBit::AuditControl,
        CapabilityBit::Setfcap,
        CapabilityBit::MacOverride,
        CapabilityBit::MacAdmin,
        CapabilityBit::Syslog,
        CapabilityBit::WakeAlarm,
        CapabilityBit::BlockSuspend,
        CapabilityBit::AuditRead,
        CapabilityBit::Perfmon,
        CapabilityBit::Bpf,
        CapabilityBit::CheckpointRestore,
    ];

    pub fn to_cap_number(&self) -> u8 {
        *self as u8
    }

    pub fn bit_mask(&self) -> u64 {
        1u64 << self.to_cap_number() as u64
    }

    pub fn add_to(&self, value: u64) -> u64 {
        value | self.bit_mask()
    }

    pub fn remove_from(&self, value: u64) -> u64 {
        value & (!self.bit_mask())
    }

    pub fn get_from(&self, value: u64) -> bool {
        (value & self.bit_mask()) == self.bit_mask()
    }

    pub fn parse_bits(value: u64) -> Vec<CapabilityBit> {
        let mut bits = Vec::new();
        for bit in Self::ALL {
            if bit.get_from(value) {
                bits.push(*bit);
            }
        }
        bits
    }

    pub fn raw_bits(bits: &[CapabilityBit]) -> u64 {
        Self::set_bits(0u64, bits)
    }

    pub fn set_bits(mut value: u64, bits: &[CapabilityBit]) -> u64 {
        for bit in bits {
            value = bit.add_to(value);
        }
        value
    }

    pub fn clear_bits(mut value: u64, bits: &[CapabilityBit]) -> u64 {
        for bit in bits {
            value = bit.remove_from(value);
        }
        value
    }
}

impl FromStr for CapabilityBit {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut input = s.trim();
        if s.starts_with("CAP_") && s.len() > 4 {
            input = &s[4..];
        }
        let refined = input.to_uppercase().trim().to_string();
        for capability in CapabilityBit::ALL {
            if refined == capability.as_ref() {
                return Ok(*capability);
            }
        }
        Err(anyhow!("unknown capability: '{}'", s))
    }
}

impl AsRef<str> for CapabilityBit {
    fn as_ref(&self) -> &'static str {
        match self {
            CapabilityBit::Chown => "CHOWN",
            CapabilityBit::DacOverride => "DAC_OVERRIDE",
            CapabilityBit::DacReadSearch => "DAC_READ_SEARCH",
            CapabilityBit::Fowner => "FOWNER",
            CapabilityBit::Fsetid => "FSETID",
            CapabilityBit::Kill => "KILL",
            CapabilityBit::Setgid => "SETGID",
            CapabilityBit::Setuid => "SETUID",
            CapabilityBit::Setpcap => "SETPCAP",
            CapabilityBit::LinuxImmutable => "LINUX_IMMUTABLE",
            CapabilityBit::NetBindService => "NET_BIND_SERVICE",
            CapabilityBit::NetBroadcast => "NET_BROADCAST",
            CapabilityBit::NetAdmin => "NET_ADMIN",
            CapabilityBit::NetRaw => "NET_RAW",
            CapabilityBit::IpcLock => "IPC_LOCK",
            CapabilityBit::IpcOwner => "IPC_OWNER",
            CapabilityBit::SysModule => "SYS_MODULE",
            CapabilityBit::SysRawIO => "SYS_RAW_IO",
            CapabilityBit::SysChroot => "SYS_CHROOT",
            CapabilityBit::SysPtrace => "SYS_PTRACE",
            CapabilityBit::SysPacct => "SYS_PACCT",
            CapabilityBit::SysAdmin => "SYS_ADMIN",
            CapabilityBit::SysBoot => "SYS_BOOT",
            CapabilityBit::SysNice => "SYS_NICE",
            CapabilityBit::SysResource => "SYS_RESOURCE",
            CapabilityBit::SysTime => "SYS_TIME",
            CapabilityBit::SysTtyConfig => "SYS_TTY_CONFIG",
            CapabilityBit::Mknod => "MKNOD",
            CapabilityBit::Lease => "LEASE",
            CapabilityBit::AuditWrite => "AUDIT_WRITE",
            CapabilityBit::AuditControl => "AUDIT_CONTROL",
            CapabilityBit::Setfcap => "SETFCAP",
            CapabilityBit::MacOverride => "MAC_OVERRIDE",
            CapabilityBit::MacAdmin => "MAC_ADMIN",
            CapabilityBit::Syslog => "SYSLOG",
            CapabilityBit::WakeAlarm => "WAKE_ALARM",
            CapabilityBit::BlockSuspend => "BLOCK_SUSPEND",
            CapabilityBit::AuditRead => "AUDIT_READ",
            CapabilityBit::Perfmon => "PERFMON",
            CapabilityBit::Bpf => "BPF",
            CapabilityBit::CheckpointRestore => "CHECKPOINT_RESTORE",
        }
    }
}

pub const PR_SET_SECUREBITS: i32 = 28;
pub const SECBIT_KEEP_CAPS: i32 = 16;
pub const SECBIT_NO_SETUID_FIXUP: i32 = 4;
pub const SECBIT_KEEP_CAPS_LOCKED: i32 = 32;

/* from <unistd.h> */

#[cfg(target_arch = "x86")]
pub const CAPGET: i32 = 184;
#[cfg(target_arch = "x86")]
pub const CAPSET: i32 = 185;

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub const CAPGET: i64 = 125;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub const CAPSET: i64 = 126;

#[cfg(all(target_arch = "x86_64", target_pointer_width = "32"))]
pub const CAPGET: i32 = 0x40000000 + 125;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "32"))]
pub const CAPSET: i32 = 0x40000000 + 126;

#[cfg(target_arch = "aarch64")]
pub const CAPGET: i64 = 90;
#[cfg(target_arch = "aarch64")]
pub const CAPSET: i64 = 91;

#[cfg(target_arch = "powerpc")]
pub const CAPGET: i32 = 183;
#[cfg(target_arch = "powerpc")]
pub const CAPSET: i32 = 184;

#[cfg(target_arch = "powerpc64")]
pub const CAPGET: i64 = 183;
#[cfg(target_arch = "powerpc64")]
pub const CAPSET: i64 = 184;

#[cfg(target_arch = "mips")]
pub const CAPGET: i32 = 4204;
#[cfg(target_arch = "mips")]
pub const CAPSET: i32 = 4205;

#[cfg(target_arch = "mips64")]
pub const CAPGET: i64 = 5123;
#[cfg(target_arch = "mips64")]
pub const CAPSET: i64 = 5124;

#[cfg(target_arch = "arm")]
pub const CAPGET: i32 = 184;
#[cfg(target_arch = "arm")]
pub const CAPSET: i32 = 185;

#[cfg(target_arch = "s390x")]
pub const CAPGET: i64 = 184;
#[cfg(target_arch = "s390x")]
pub const CAPSET: i64 = 185;

#[cfg(target_arch = "sparc")]
pub const CAPGET: i64 = 21;
#[cfg(target_arch = "sparc")]
pub const CAPSET: i64 = 22;

#[cfg(target_arch = "sparc64")]
pub const CAPGET: i64 = 21;
#[cfg(target_arch = "sparc64")]
pub const CAPSET: i64 = 22;

#[cfg(target_arch = "riscv64")]
pub const CAPGET: i64 = 90;
#[cfg(target_arch = "riscv64")]
pub const CAPSET: i64 = 91;

#[cfg(target_arch = "loongarch64")]
pub const CAPGET: i64 = 90;
#[cfg(target_arch = "loongarch64")]
pub const CAPSET: i64 = 91;

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

#[repr(C)]
struct CapInternalHeader {
    pub version: u32,
    pub pid: i32,
}

#[repr(C)]
#[derive(Default)]
struct CapInternalData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[repr(C)]
struct CapInternalResult {
    pub header: CapInternalHeader,
    pub data: [CapInternalData; 2],
}

pub struct CapResult {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

fn capget(result: &mut CapInternalResult) -> anyhow::Result<()> {
    unsafe {
        if syscall(libc::SYS_capget, &result.header, &result.data) < 0 {
            Err(anyhow!("capget(2) failed"))
        } else {
            Ok(())
        }
    }
}

fn capset(result: &CapInternalResult) -> anyhow::Result<()> {
    unsafe {
        let err = syscall(libc::SYS_capset, &result.header, &result.data);
        if err < 0 {
            let effective =
                ((result.data[1].effective as u64) << 32) | result.data[0].effective as u64;
            let permitted =
                ((result.data[1].permitted as u64) << 32) | result.data[0].permitted as u64;
            let inheritable =
                ((result.data[1].inheritable as u64) << 32) | result.data[0].inheritable as u64;

            Err(anyhow!(
                "capset(2) failed: {:x} {:x} {:x} (error = {err})",
                effective,
                permitted,
                inheritable
            ))
        } else {
            Ok(())
        }
    }
}

pub fn get_caps() -> anyhow::Result<CapResult> {
    let pid = std::process::id() as i32;
    let mut iresult = CapInternalResult {
        header: CapInternalHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid,
        },
        data: [CapInternalData::default(), CapInternalData::default()],
    };

    capget(&mut iresult)?;

    // Linux capability v3: data[0] = caps 0-31, data[1] = caps 32+
    let effective = ((iresult.data[1].effective as u64) << 32) | iresult.data[0].effective as u64;
    let permitted = ((iresult.data[1].permitted as u64) << 32) | iresult.data[0].permitted as u64;
    let inheritable =
        ((iresult.data[1].inheritable as u64) << 32) | iresult.data[0].inheritable as u64;

    let finalresult = CapResult {
        effective,
        permitted,
        inheritable,
    };

    debug!(
        "get capabilities of pid {}: eff={:x} perm={:x} inh={:?}",
        iresult.header.pid, effective, permitted, inheritable
    );

    Ok(finalresult)
}

pub fn set_caps(caps: CapResult) -> anyhow::Result<()> {
    let pid = std::process::id() as i32;

    debug!(
        "set capabilities of pid {}: eff={:x} perm={:x} inh={:x}",
        pid, caps.effective, caps.permitted, caps.inheritable
    );

    let iresult = CapInternalResult {
        header: CapInternalHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid,
        },
        // Linux capability v3: data[0] = caps 0-31, data[1] = caps 32+
        data: [
            CapInternalData {
                effective: caps.effective as u32,
                permitted: caps.permitted as u32,
                inheritable: caps.inheritable as u32,
            },
            CapInternalData {
                effective: (caps.effective >> 32) as u32,
                permitted: (caps.permitted >> 32) as u32,
                inheritable: (caps.inheritable >> 32) as u32,
            },
        ],
    };

    capset(&iresult)?;

    Ok(())
}

pub fn set_keep_caps() -> anyhow::Result<()> {
    // Lock securebits to prevent clearing before cap drop.
    // SECBIT_NO_SETUID_FIXUP (4) | SECBIT_NO_SETUID_FIXUP_LOCKED (8) | SECBIT_KEEP_CAPS_LOCKED (32)
    let bits = SECBIT_NO_SETUID_FIXUP | 8 | SECBIT_KEEP_CAPS_LOCKED;
    let ret = unsafe { libc::prctl(PR_SET_SECUREBITS, bits) };
    if ret < 0 {
        Err(anyhow!(
            "failed to set securebits: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}
