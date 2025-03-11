use anyhow::{anyhow, Result};
use libc::syscall;

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

fn capget(result: &mut CapInternalResult) -> Result<()> {
    unsafe {
        if syscall(libc::SYS_capget, &result.header, &result.data) < 0 {
            Err(anyhow!("capget(2) failed"))
        } else {
            Ok(())
        }
    }
}

fn capset(result: &CapInternalResult) -> Result<()> {
    unsafe {
        if syscall(libc::SYS_capset, &result.header, &result.data) < 0 {
            Err(anyhow!("capset(2) failed"))
        } else {
            Ok(())
        }
    }
}

pub fn get_caps() -> Result<CapResult> {
    let pid = std::process::id() as i32;
    let mut iresult = CapInternalResult {
        header: CapInternalHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid,
        },
        data: [CapInternalData::default(), CapInternalData::default()],
    };

    capget(&mut iresult)?;

    let effective = ((iresult.data[0].effective as u64) << 32) | iresult.data[1].effective as u64;
    let permitted = ((iresult.data[0].permitted as u64) << 32) | iresult.data[1].permitted as u64;
    let inheritable =
        ((iresult.data[0].inheritable as u64) << 32) | iresult.data[1].inheritable as u64;

    let finalresult = CapResult {
        effective,
        permitted,
        inheritable,
    };

    Ok(finalresult)
}

pub fn set_caps(caps: CapResult) -> Result<()> {
    let iresult = CapInternalResult {
        header: CapInternalHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: -1,
        },
        data: [
            CapInternalData {
                effective: (caps.effective >> 32) as u32,
                permitted: (caps.permitted >> 32) as u32,
                inheritable: (caps.inheritable >> 32) as u32,
            },
            CapInternalData {
                effective: caps.effective as u32,
                permitted: caps.permitted as u32,
                inheritable: caps.inheritable as u32,
            },
        ],
    };

    capset(&iresult)?;

    Ok(())
}
