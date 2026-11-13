// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{fs::vfs::path::FsPath, prelude::*, syscall::constants::MAX_FILENAME_LEN};

pub(super) fn sys_chroot(path_ptr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let path_name = ctx.user_space().read_cstring(path_ptr, MAX_FILENAME_LEN)?;
    debug!("path_name = {:?}", path_name);

    let fs_ref = ctx.thread_local.borrow_fs();
    let path = {
        let fs_path = FsPath::try_from(path_name.to_bytes())?;
        fs_ref.resolver().read().lookup(&fs_path)?
    };
    fs_ref.resolver().write().chroot(path, ctx)?;
    Ok(SyscallReturn::Return(0))
}
