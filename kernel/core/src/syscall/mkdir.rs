// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs,
    fs::{
        file::{InodeMode, InodeType, file_table::RawFileDesc},
        vfs::path::{AT_FDCWD, EmptyPathStr, FsPath},
    },
    prelude::*,
    syscall::constants::MAX_FILENAME_LEN,
};

pub(super) fn sys_mkdirat(
    dirfd: RawFileDesc,
    path_addr: Vaddr,
    mode: u16,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let path = ctx.user_space().read_cstring(path_addr, MAX_FILENAME_LEN)?;
    debug!("dirfd = {}, path = {:?}, mode = {}", dirfd, path, mode);

    let fs_ref = ctx.thread_local.borrow_fs();
    let (dir_path, name) = {
        let fs_path = FsPath::from_fd_at_bytes(dirfd, path.to_bytes(), EmptyPathStr::Reject)?;
        fs_ref
            .resolver()
            .read()
            .lookup_unresolved_no_follow(&fs_path)?
            .into_parent_and_basename()?
    };

    dir_path.new_child_bytes_inheriting(
        &name,
        InodeType::Dir,
        InodeMode::from_bits_truncate(mode),
        fs_ref.umask().get(),
    )?;
    fs::vfs::notify::on_mkdir(&dir_path, || name);
    Ok(SyscallReturn::Return(0))
}

pub(super) fn sys_mkdir(path_addr: Vaddr, mode: u16, ctx: &Context) -> Result<SyscallReturn> {
    sys_mkdirat(AT_FDCWD, path_addr, mode, ctx)
}
