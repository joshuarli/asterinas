// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    fs::{
        self,
        file::{
            InodeHandle, InodeType, StatusFlags,
            file_table::{RawFileDesc, WithFileTable},
        },
    },
    prelude::*,
};

const MAX_RW_COUNT: usize = 0x7fff_f000;
const BUFFER_SIZE: usize = 16 * PAGE_SIZE;

pub(super) fn sys_copy_file_range(
    in_fd: RawFileDesc,
    in_offset_ptr: Vaddr,
    out_fd: RawFileDesc,
    out_offset_ptr: Vaddr,
    len: usize,
    flags: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "in_fd = {}, in_offset_ptr = {:#x}, out_fd = {}, out_offset_ptr = {:#x}, len = {:#x}, flags = {:#x}",
        in_fd, in_offset_ptr, out_fd, out_offset_ptr, len, flags
    );

    if flags != 0 {
        return_errno_with_message!(Errno::EINVAL, "no flags are defined");
    }

    let (in_file, out_file) = ctx
        .thread_local
        .borrow_file_table_mut()
        .read_with(|inner| {
            let in_file = inner.get_file(in_fd.try_into()?)?.clone();
            let out_file = inner.get_file(out_fd.try_into()?)?.clone();
            Ok::<_, Error>((in_file, out_file))
        })?;

    if !in_file.access_mode().is_readable()
        || !out_file.access_mode().is_writable()
        || in_file.status_flags().contains(StatusFlags::O_PATH)
        || out_file.status_flags().contains(StatusFlags::O_PATH)
        || out_file.status_flags().contains(StatusFlags::O_APPEND)
    {
        return_errno_with_message!(Errno::EBADF, "the files are not open for copying");
    }

    let (Some(in_handle), Some(out_handle)) = (
        in_file.downcast_ref::<InodeHandle>(),
        out_file.downcast_ref::<InodeHandle>(),
    ) else {
        return_errno_with_message!(Errno::EINVAL, "both files must be regular files");
    };
    let (in_inode, out_inode) = (in_handle.path().inode(), out_handle.path().inode());
    if in_inode.type_() == InodeType::Dir || out_inode.type_() == InodeType::Dir {
        return_errno_with_message!(Errno::EISDIR, "a file is a directory");
    }
    if in_inode.type_() != InodeType::File || out_inode.type_() != InodeType::File {
        return_errno_with_message!(Errno::EINVAL, "both files must be regular files");
    }
    if !Arc::ptr_eq(&in_inode.fs(), &out_inode.fs()) {
        return_errno_with_message!(Errno::EXDEV, "the files are on different file systems");
    }

    let explicit_in = read_position(in_offset_ptr, ctx)?;
    let explicit_out = read_position(out_offset_ptr, ctx)?;
    let same_handle = core::ptr::eq(in_handle, out_handle);
    let input_first = (in_handle as *const InodeHandle as usize)
        <= (out_handle as *const InodeHandle as usize);
    let mut in_guard = None;
    let mut out_guard = None;
    if explicit_in.is_none() && (explicit_out.is_some() || input_first) {
        in_guard = Some(in_handle.lock_offset());
    }
    if explicit_out.is_none() && !(same_handle && in_guard.is_some()) {
        out_guard = Some(out_handle.lock_offset());
    }
    if explicit_in.is_none() && in_guard.is_none() && !(same_handle && out_guard.is_some()) {
        in_guard = Some(in_handle.lock_offset());
    }
    let in_pos = explicit_in.unwrap_or_else(|| {
        **in_guard.as_ref().or(out_guard.as_ref()).expect("input offset is locked")
    });
    let out_pos = explicit_out.unwrap_or_else(|| {
        **out_guard.as_ref().or(in_guard.as_ref()).expect("output offset is locked")
    });

    let len = len.min(MAX_RW_COUNT);
    if in_pos.checked_add(len).is_none_or(|end| end > i64::MAX as usize)
        || out_pos.checked_add(len).is_none_or(|end| end > i64::MAX as usize)
    {
        return_errno_with_message!(Errno::EOVERFLOW, "a position overflows");
    }

    let in_size = in_handle.path().size();
    let len = len.min(in_size.saturating_sub(in_pos));

    if Arc::ptr_eq(in_inode, out_inode) && out_pos + len > in_pos && out_pos < in_pos + len {
        return_errno_with_message!(Errno::EINVAL, "the ranges overlap in one file");
    }

    let mut buffer = vec![0u8; BUFFER_SIZE.min(len)].into_boxed_slice();
    let mut copied = 0;
    while copied < len {
        let chunk = buffer.len().min(len - copied);
        let read_len = match in_file.read_bytes_at(in_pos + copied, &mut buffer[..chunk]) {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(error) if copied == 0 => return Err(error),
            Err(_) => break,
        };
        match out_file.write_bytes_at(out_pos + copied, &buffer[..read_len]) {
            Ok(written) => {
                copied += written;
                if written < read_len {
                    break;
                }
            }
            Err(error) if copied == 0 => return Err(error),
            Err(_) => break,
        }
    }

    if copied > 0 {
        if in_offset_ptr == 0 {
            **in_guard.as_mut().or(out_guard.as_mut()).expect("input offset is locked") = in_pos + copied;
        } else {
            ctx.user_space().write_val(in_offset_ptr, &((in_pos + copied) as i64))?;
        }
        if out_offset_ptr == 0 {
            **out_guard.as_mut().or(in_guard.as_mut()).expect("output offset is locked") = out_pos + copied;
        } else {
            ctx.user_space().write_val(out_offset_ptr, &((out_pos + copied) as i64))?;
        }
        fs::vfs::notify::on_access(&in_file);
        fs::vfs::notify::on_modify(&out_file);
    }

    Ok(SyscallReturn::Return(copied as _))
}

fn read_position(offset_ptr: Vaddr, ctx: &Context) -> Result<Option<usize>> {
    if offset_ptr == 0 {
        return Ok(None);
    }

    let offset: i64 = ctx.user_space().read_val(offset_ptr)?;
    usize::try_from(offset)
        .map(Some)
        .map_err(|_| Error::with_message(Errno::EOVERFLOW, "a negative offset"))
}
