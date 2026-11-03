// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    dispatch_ioctl,
    fs::file::{
        FileLike, InodeHandle, InodeType, StatusFlags,
        file_table::{FdFlags, RawFileDesc, WithFileTable, get_file_fast},
    },
    prelude::*,
    process::posix_thread::FileTableRefMut,
    util::ioctl::RawIoctl,
};

pub(super) fn sys_ioctl(
    raw_fd: RawFileDesc,
    cmd: u32,
    arg: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let raw_ioctl = RawIoctl::new(cmd, arg);
    debug!("raw_fd = {}, raw_ioctl = {:#x?}", raw_fd, raw_ioctl,);

    let mut file_table = ctx.thread_local.borrow_file_table_mut();

    // First, handle the ioctl command that affects the file descriptor.
    if let Some(res) = handle_fd_ioctl(&mut file_table, raw_fd, raw_ioctl) {
        res?;
        return Ok(SyscallReturn::Return(0));
    }

    let file = get_file_fast!(&mut file_table, raw_fd.try_into()?);

    // Then, handle the ioctl command the affects the file description.
    let res = if let Some(res) = handle_file_ioctl(&**file, raw_ioctl) {
        res?;
        0
    } else {
        let file_owned = file.into_owned();
        // We have to drop `file_table` because some I/O command will modify the file table
        // (e.g., TIOCGPTPEER).
        drop(file_table);
        file_owned.ioctl(raw_ioctl)?
    };

    Ok(SyscallReturn::Return(res as _))
}

mod ioctl_defs {
    use crate::{
        ioc,
        util::ioctl::{InData, NoData, PassByVal},
    };

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/asm-generic/ioctls.h>

    pub(super) type SetNonBlocking    = ioc!(FIONBIO,  0x5421, InData<i32>);
    pub(super) type SetAsync          = ioc!(FIOASYNC, 0x5452, InData<i32>);

    pub(super) type SetNotCloseOnExec = ioc!(FIONCLEX, 0x5450, NoData);
    pub(super) type SetCloseOnExec    = ioc!(FIOCLEX,  0x5451, NoData);

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/fs.h>
    pub(super) type CloneFile         = ioc!(FICLONE,  0x94, 9, InData<i32, PassByVal>);
}

fn handle_fd_ioctl(
    file_table: &mut FileTableRefMut,
    raw_fd: RawFileDesc,
    raw_ioctl: RawIoctl,
) -> Option<Result<()>> {
    use ioctl_defs::*;

    dispatch_ioctl!(match raw_ioctl {
        SetNotCloseOnExec => {
            // Clears the close-on-exec flag of the file.
            // Follow the implementation of `fcntl()`.

            Some(file_table.read_with(|inner| {
                let entry = inner.get_entry(raw_fd.try_into()?)?;
                // FIXME: This is racy.
                entry.set_flags(entry.flags() - FdFlags::CLOEXEC);
                Ok(())
            }))
        }
        SetCloseOnExec => {
            // Sets the close-on-exec flag of the file.
            // Follow the implementation of `fcntl()`.

            Some(file_table.read_with(|inner| {
                let entry = inner.get_entry(raw_fd.try_into()?)?;
                // FIXME: This is racy.
                entry.set_flags(entry.flags() | FdFlags::CLOEXEC);
                Ok(())
            }))
        }
        cmd @ CloneFile => {
            Some(file_table.read_with(|inner| {
                let source = inner.get_file(cmd.get().try_into()?)?.clone();
                let destination = inner.get_file(raw_fd.try_into()?)?;
                clone_file(&source, destination)
            }))
        }
        _ => None,
    })
}

fn clone_file(source: &Arc<dyn FileLike>, destination: &Arc<dyn FileLike>) -> Result<()> {
    if source.status_flags().contains(StatusFlags::O_PATH)
        || destination.status_flags().contains(StatusFlags::O_PATH)
    {
        return_errno_with_message!(Errno::EBADF, "a file is opened as a path");
    }
    let (Some(source_handle), Some(destination_handle)) = (
        source.downcast_ref::<InodeHandle>(),
        destination.downcast_ref::<InodeHandle>(),
    ) else {
        return_errno_with_message!(Errno::EINVAL, "both files must be regular files");
    };
    let (source_inode, destination_inode) = (
        source_handle.path().inode(),
        destination_handle.path().inode(),
    );

    if !Arc::ptr_eq(&source_inode.fs(), &destination_inode.fs()) {
        return_errno_with_message!(Errno::EXDEV, "the files are on different file systems");
    }
    if !source.access_mode().is_readable() || !destination.access_mode().is_writable() {
        return_errno_with_message!(Errno::EBADF, "the files are not open for cloning");
    }
    if source_inode.type_() == InodeType::Dir || destination_inode.type_() == InodeType::Dir {
        return_errno_with_message!(Errno::EISDIR, "a file is a directory");
    }
    if source_inode.type_() != InodeType::File || destination_inode.type_() != InodeType::File {
        return_errno_with_message!(Errno::EINVAL, "both files must be regular files");
    }

    return_errno_with_message!(Errno::EOPNOTSUPP, "the file system cannot clone files");
}

fn handle_file_ioctl(file: &dyn FileLike, raw_ioctl: RawIoctl) -> Option<Result<()>> {
    use ioctl_defs::*;

    dispatch_ioctl!(match raw_ioctl {
        cmd @ SetNonBlocking => {
            let handler = || {
                let is_nonblocking = cmd.read()? != 0;

                file.update_status_nonblock(is_nonblocking);
                Ok(())
            };
            Some(handler())
        }
        cmd @ SetAsync => {
            let handler = || {
                let is_async = cmd.read()? != 0;

                // Setting the `O_ASYNC` flag will cause the kernel to send the owner process a
                // `SIGIO` signal when input/output is possible. The user should first call
                // `fcntl(fd, F_SETOWN, pid)` to specify the process to be notified.
                file.update_status_async(is_async)
            };
            Some(handler())
        }
        _ => None,
    })
}
