use std::ffi::c_int;

use serde::{Deserialize, Serialize};

pub const CLONE_NEWTIME: c_int = 0x00000080;
pub const CLONE_NEWNS: c_int = 0x00020000;
pub const CLONE_NEWCGROUP: c_int = 0x02000000;
pub const CLONE_NEWUTS: c_int = 0x04000000;
pub const CLONE_NEWIPC: c_int = 0x08000000;
pub const CLONE_NEWUSER: c_int = 0x10000000;
pub const CLONE_NEWPID: c_int = 0x20000000;
pub const CLONE_NEWNET: c_int = 0x40000000;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Namespace {
    Mount,
    Uts,
    Ipc,
    User,
    Pid,
    Net,
    Cgroup,
    Time,
}

pub fn to_clone_flags(ns: Namespace) -> c_int {
    match ns {
        Namespace::Mount => CLONE_NEWNS,
        Namespace::Uts => CLONE_NEWUTS,
        Namespace::Ipc => CLONE_NEWIPC,
        Namespace::User => CLONE_NEWUSER,
        Namespace::Pid => CLONE_NEWPID,
        Namespace::Net => CLONE_NEWNET,
        Namespace::Cgroup => CLONE_NEWCGROUP,
        Namespace::Time => CLONE_NEWTIME,
    }
}
