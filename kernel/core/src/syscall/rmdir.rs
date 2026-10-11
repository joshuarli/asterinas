// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::{
        file::file_table::RawFileDesc,
        vfs::path::{AT_FDCWD, EmptyPathStr, FsPath, SplitPath, SplitPathError},
    },
    prelude::*,
    syscall::constants::MAX_FILENAME_LEN,
};

pub(super) fn sys_rmdir(path_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    do_rmdirat(AT_FDCWD, path_addr, ctx)
}

pub(super) fn do_rmdirat(
    dirfd: RawFileDesc,
    path_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let path_name = ctx.user_space().read_cstring(path_addr, MAX_FILENAME_LEN)?;
    debug!("dirfd = {}, path_addr = {:?}", dirfd, path_addr);

    let (dir_path, name) = {
        let (parent_path_name, target_name) = path_name
            .to_bytes()
            .split_dirname_and_basename()
            .map_err(SplitPathError::reject_root_as_busy)?;
        let fs_path = FsPath::from_fd_at_bytes(dirfd, parent_path_name, EmptyPathStr::Reject)?;
        (
            ctx.thread_local
                .borrow_fs()
                .resolver()
                .read()
                .lookup(&fs_path)?,
            target_name.to_vec(),
        )
    };

    dir_path.rmdir_bytes(&name)?;
    Ok(SyscallReturn::Return(0))
}
