// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{
        file::InodeMode,
        fs_impls::ramfs::{self, RamFs, RootAttributes},
        pseudofs::AnonDeviceId,
        vfs::{
            file_system::{FileSystem, SuperBlock},
            inode::RevalidationPolicy,
            registry::{FsCreationCtx, FsProperties, FsType},
        },
    },
    prelude::*,
    process::{Uid, Gid},
};

const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The temporary file system (tmpfs) structure.
//
// TODO: `TmpFs` currently aliases `RamFs` and relies on `RamFs::new_tmpfs()`
// to create tmpfs-flavored ramfs instances. In the future we need to
// implement a dedicated tmpfs with tmpfs-specific features such as memory
// limits and swap support.
pub(crate) type TmpFs = RamFs;

impl TmpFs {
    /// Creates a tmpfs filesystem instance.
    pub(in crate::fs) fn new_tmpfs(root_attributes: RootAttributes) -> Arc<Self> {
        Self::new_tmpfs_backing("tmpfs", RevalidationPolicy::empty(), root_attributes)
    }

    /// Creates a tmpfs-backed filesystem instance with a custom filesystem name
    /// and directory-entry revalidation policy.
    pub(in crate::fs) fn new_tmpfs_backing(
        name: &'static str,
        revalidation_policy: RevalidationPolicy,
        root_attributes: RootAttributes,
    ) -> Arc<Self> {
        let anon_device_id = AnonDeviceId::acquire().expect("no device ID is available for tmpfs");
        let sb = {
            let mut super_block = SuperBlock::new(
                TMPFS_MAGIC,
                ramfs::BLOCK_SIZE,
                ramfs::NAME_MAX,
                anon_device_id.id(),
            );
            let max_blocks = default_max_blocks();
            let max_inodes = default_max_inodes();
            super_block.blocks = max_blocks;
            super_block.bfree = max_blocks;
            super_block.bavail = max_blocks;
            super_block.files = max_inodes;
            super_block.ffree = max_inodes;
            super_block
        };
        Self::new_with_sb(name, anon_device_id, sb, revalidation_policy, root_attributes)
    }
}

// FIXME: These defaults are only a rough approximation for tmpfs-over-ramfs.
// A dedicated tmpfs implementation should replace them with real tmpfs limit
// and accounting semantics.
fn default_max_blocks() -> usize {
    crate::vm::mem_total() / PAGE_SIZE / 2
}
fn default_max_inodes() -> usize {
    crate::vm::mem_total() / PAGE_SIZE / 2
}

pub(super) struct TmpFsType;

impl FsType for TmpFsType {
    type Key = ();

    fn name(&self) -> &'static str {
        "tmpfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, fs_creation_ctx: &mut FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let ctx = fs_creation_ctx.ctx().ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "the tmpfs mount has no task context")
        })?;
        let credentials = ctx.posix_thread.credentials();
        let mut attributes = RootAttributes {
            mode: InodeMode::from_bits_truncate(0o1777),
            uid: credentials.fsuid(),
            gid: credentials.fsgid(),
        };
        for option in fs_creation_ctx.args().unwrap_or("").split(',') {
            let (name, value) = option.split_once('=').unwrap_or((option, ""));
            match name {
                "mode" => {
                    let mode = parse_mount_u32(value, 8)?;
                    attributes.mode = InodeMode::from_bits_truncate((mode & 0o7777) as u16);
                }
                "uid" => {
                    let uid = parse_owner_id(value)?;
                    attributes.uid = Uid::from(uid);
                }
                "gid" => {
                    let gid = parse_owner_id(value)?;
                    attributes.gid = Gid::from(gid);
                }
                _ => {}
            }
        }
        Ok(TmpFs::new_tmpfs(attributes))
    }

    fn sysnode(&self) -> Option<Arc<dyn aster_systree::SysNode>> {
        None
    }
}

fn parse_mount_u32(value: &str, base: u32) -> Result<u32> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix) = if base != 0 {
        (value, base)
    } else if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        (hex, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return_errno_with_message!(Errno::EINVAL, "invalid tmpfs root attribute");
    }
    u32::from_str_radix(digits, radix)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid tmpfs root attribute"))
}

fn parse_owner_id(value: &str) -> Result<u32> {
    let id = parse_mount_u32(value, 0)?;
    if id == u32::MAX {
        return_errno_with_message!(Errno::EINVAL, "invalid tmpfs root owner");
    }
    Ok(id)
}
