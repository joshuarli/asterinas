// SPDX-License-Identifier: MPL-2.0

pub(crate) use cgroup_ns::CgroupNamespace;
pub(crate) use controller::cpu::{CpuStatKind, charge_cpu_time};
use fs::CgroupFsType;
pub(in crate::fs) use systree_node::CgroupSystem;
pub(crate) use systree_node::{CgroupMembership, CgroupNode, CgroupSysNode};

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "cgroup: "
    };
}

mod cgroup_ns;
mod controller;
mod fs;
mod inode;
mod systree_node;

// This method should be called during kernel file system initialization,
// _after_ `aster_systree::init`.
pub(super) fn init() {
    crate::fs::vfs::registry::register(&CgroupFsType).unwrap();
}

pub(crate) fn current_cgroup_inode() -> u64 {
    use aster_systree::SysObj;
    use crate::current;
    let process = current!();
    let cgroup = process.cgroup();
    if let Some(node) = cgroup.get() {
        crate::fs::utils::systree_inode::ino::from_sysnode_id(node.id())
    } else {
        let root = CgroupNamespace::get_init_singleton().root_node();
        crate::fs::utils::systree_inode::ino::from_sysnode_id(root.id())
    }
}
