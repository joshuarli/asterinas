// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{fs::vfs::path::{MNT_UNIQUE_ID_MIN, Path}, prelude::*};

const SB_BASIC: u64 = 1;
const MNT_BASIC: u64 = 2;
const PROPAGATE_FROM: u64 = 4;
const MNT_ROOT: u64 = 8;
const MNT_POINT: u64 = 16;
const FS_TYPE: u64 = 32;
const FIXED_SIZE: usize = size_of::<Statmount>();
const _: () = assert!(FIXED_SIZE == 512);

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct MntIdReq {
    size: u32,
    spare: u32,
    id: u64,
    mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct Statmount {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    spare: [u64; 50],
}

pub(super) fn sys_statmount(req_ptr: Vaddr, buf_ptr: Vaddr, buf_size: usize, flags: u32, ctx: &Context) -> Result<SyscallReturn> {
    if flags != 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid statmount flags");
    }
    let user = ctx.user_space();
    let req: MntIdReq = user.read_val(req_ptr)?;
    if !matches!(req.size, 24 | 32) || req.spare != 0 || req.id < MNT_UNIQUE_ID_MIN {
        return_errno_with_message!(Errno::EINVAL, "invalid mount request");
    }
    if req.size == 32 && user.read_val::<u64>(req_ptr + 24)? != 0 {
        return_errno_with_message!(Errno::EINVAL, "unsupported mount namespace");
    }
    let ns_proxy = ctx.thread_local.borrow_ns_proxy();
    let ns = ns_proxy.unwrap().mnt_ns();
    let mount = ns.lookup_by_unique_id(req.id).ok_or_else(|| Error::with_message(Errno::ENOENT, "no such mount"))?;
    let fs = ctx.thread_local.borrow_fs();
    let resolver = fs.resolver().read();
    let parent = mount.parent().and_then(|parent| parent.upgrade());
    let parent_mount = parent.as_ref().unwrap_or(&mount);
    let sb = mount.fs().sb();
    let (propagation, peer, master) = mount.statmount_propagation();
    let flags = mount.flags().bits();
    let mut result = Statmount {
        size: FIXED_SIZE as u32, mnt_opts: 0, mask: req.mask & (SB_BASIC | MNT_BASIC | PROPAGATE_FROM | MNT_ROOT | MNT_POINT | FS_TYPE),
        sb_dev_major: sb.container_dev_id.major().get() as u32, sb_dev_minor: sb.container_dev_id.minor().get(), sb_magic: sb.magic,
        sb_flags: sb.flags as u32 & ((1 << 0) | (1 << 4) | (1 << 7) | (1 << 25)), fs_type: 0,
        mnt_id: mount.unique_id(), mnt_parent_id: parent_mount.unique_id(), mnt_id_old: mount.id(), mnt_parent_id_old: parent_mount.id(),
        mnt_attr: (flags & 15) as u64 | if flags & (1 << 10) != 0 { 0x10 } else if flags & (1 << 24) != 0 { 0x20 } else { 0 } | if flags & (1 << 11) != 0 { 0x80 } else { 0 } | if flags & (1 << 8) != 0 { 0x200000 } else { 0 },
        mnt_propagation: propagation, mnt_peer_group: peer, mnt_master: master, propagate_from: 0, mnt_root: 0, mnt_point: 0, spare: [0; 50],
    };
    let mut strings = Vec::new();
    if req.mask & FS_TYPE != 0 {
        result.fs_type = strings.len() as u32;
        strings.extend_from_slice(mount.fs().name().as_bytes());
        strings.push(0);
    }
    if req.mask & MNT_ROOT != 0 {
        result.mnt_root = strings.len() as u32;
        let root = if Arc::ptr_eq(&mount, resolver.root().mount_node()) { resolver.root().dentry().path_name() } else { mount.root_dentry().path_name() };
        strings.extend_from_slice(root.as_bytes());
        strings.push(0);
    }
    if req.mask & MNT_POINT != 0 {
        result.mnt_point = strings.len() as u32;
        let point = if Arc::ptr_eq(&mount, resolver.root().mount_node()) { b"/".to_vec() } else if let (Some(parent), Some(point)) = (parent, mount.mountpoint()) { resolver.make_abs_path(&Path::new(parent, point)).into_bytes() } else { b"/".to_vec() };
        strings.extend_from_slice(&point);
        strings.push(0);
    }
    let size = FIXED_SIZE + strings.len();
    if size > buf_size {
        return_errno_with_message!(Errno::EOVERFLOW, "statmount buffer too small");
    }
    result.size = size as u32;
    user.write_val(buf_ptr, &result)?;
    user.write_bytes(buf_ptr + FIXED_SIZE, &strings)?;
    Ok(SyscallReturn::Return(0))
}
