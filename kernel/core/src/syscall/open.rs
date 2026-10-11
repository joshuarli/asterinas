// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs,
    fs::{
        file::{
            AccessMode, CreationFlags, FileLike, InodeHandle, InodeMode, InodeType, OpenArgs,
            StatusFlags,
            file_table::{FdFlags, RawFileDesc},
        },
        vfs::{
            inode::HardLinkability,
            path::{
                AT_FDCWD, EmptyPathStr, FsPath, LookupResult, OpenResolveFlags, PathResolver,
                Path, path_lookup_read_lock,
            },
        },
    },
    prelude::*,
    syscall::constants::MAX_FILENAME_LEN,
    util::CopyCompat,
};

pub(super) fn sys_openat(
    dirfd: RawFileDesc,
    path_addr: Vaddr,
    flags: u32,
    mode: u16,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let path = ctx.user_space().read_cstring(path_addr, MAX_FILENAME_LEN)?;
    debug!(
        "dirfd = {}, path = {:?}, flags = {}, mode = {}",
        dirfd, path, flags, mode
    );

    let file_handle = {
        let path = path.to_string_lossy();
        let fs_path = FsPath::from_fd_at(dirfd, path.as_ref(), EmptyPathStr::Reject)?;

        let fs_ref = ctx.thread_local.borrow_fs();
        let mask_mode = mode & !fs_ref.umask().get();

        let path_resolver = fs_ref.resolver().read();
        do_open(
            &path_resolver,
            &fs_path,
            flags,
            InodeMode::from_bits_truncate(mask_mode),
        )
        .map_err(|err| match err.error() {
            Errno::EINTR => Error::new(Errno::ERESTARTSYS),
            _ => err,
        })?
    };

    let fd = {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        let fd_flags =
            if CreationFlags::from_bits_truncate(flags).contains(CreationFlags::O_CLOEXEC) {
                FdFlags::CLOEXEC
            } else {
                FdFlags::empty()
            };
        file_table_locked.insert(file_handle.clone(), fd_flags)
    };
    fs::vfs::notify::on_open(file_handle.common());
    Ok(SyscallReturn::Return(fd.into()))
}

pub(super) fn sys_open(
    path_addr: Vaddr,
    flags: u32,
    mode: u16,
    ctx: &Context,
) -> Result<SyscallReturn> {
    sys_openat(AT_FDCWD, path_addr, flags, mode, ctx)
}

pub(super) fn sys_openat2(
    dirfd: RawFileDesc,
    path_addr: Vaddr,
    how_addr: Vaddr,
    size: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if size < size_of::<OpenHow>() {
        return_errno_with_message!(Errno::EINVAL, "open_how is too small");
    }
    if size > PAGE_SIZE {
        return_errno_with_message!(Errno::E2BIG, "open_how is too large");
    }

    let how = ctx.user_space().read_val_compat::<OpenHow>(how_addr, size)?;
    if how.flags > u32::MAX as u64 {
        return_errno_with_message!(Errno::EINVAL, "open flags contain unsupported bits");
    }
    let flags = how.flags as u32;
    if flags & !OPENAT2_SUPPORTED_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "open flags contain unsupported bits");
    }
    if flags & StatusFlags::O_PATH.bits() != 0 && flags & !OPENAT2_PATH_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "O_PATH is combined with unsupported flags");
    }
    let Some(resolve) = OpenResolveFlags::from_bits(how.resolve) else {
        return_errno_with_message!(Errno::EINVAL, "resolve flags contain unsupported bits");
    };
    if resolve.contains(OpenResolveFlags::BENEATH | OpenResolveFlags::IN_ROOT) {
        return_errno_with_message!(Errno::EINVAL, "BENEATH and IN_ROOT cannot be combined");
    }
    let creates_file = flags & (CreationFlags::O_CREAT.bits() | CreationFlags::O_TMPFILE.bits()) != 0;
    if creates_file {
        if how.mode & !OPENAT2_MODE_MASK != 0 {
            return_errno_with_message!(Errno::EINVAL, "mode contains unsupported bits");
        }
    } else if how.mode != 0 {
        return_errno_with_message!(Errno::EINVAL, "mode requires O_CREAT or O_TMPFILE");
    }

    let path = ctx.user_space().read_cstring(path_addr, MAX_FILENAME_LEN)?;
    debug!("dirfd = {}, path = {:?}, how = {:?}", dirfd, path, how);

    let file_handle = {
        let fs_ref = ctx.thread_local.borrow_fs();
        let path_resolver = fs_ref.resolver().read();
        // Keep path ancestry stable until the file is opened. Directory renames and mount
        // topology changes take the write side of these locks.
        let _path_lookup_guard = path_lookup_read_lock();
        let mode = InodeMode::from_bits_truncate((how.mode as u16) & !fs_ref.umask().get());
        let open_args = OpenArgs::from_flags_and_mode(flags, mode)?;
        let lookup_res = path_resolver.lookup_unresolved_openat2(
            dirfd,
            &path.to_string_lossy(),
            open_args.follow_tail_link(),
            resolve,
        );
        lookup_res
            .and_then(|lookup_res| do_open_resolved(lookup_res, open_args))
            .map_err(|err| match err.error() {
                Errno::EINTR => Error::new(Errno::ERESTARTSYS),
                _ => err,
            })?
    };

    let fd = {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        let fd_flags = if CreationFlags::from_bits_truncate(flags).contains(CreationFlags::O_CLOEXEC)
        {
            FdFlags::CLOEXEC
        } else {
            FdFlags::empty()
        };
        file_table_locked.insert(file_handle.clone(), fd_flags)
    };
    fs::vfs::notify::on_open(file_handle.common());
    Ok(SyscallReturn::Return(fd.into()))
}

const OPENAT2_SUPPORTED_FLAGS: u32 =
    CreationFlags::all().bits() | StatusFlags::all().bits() | 0b11;
const OPENAT2_PATH_FLAGS: u32 = StatusFlags::O_PATH.bits()
    | CreationFlags::O_DIRECTORY.bits()
    | CreationFlags::O_NOFOLLOW.bits()
    | CreationFlags::O_CLOEXEC.bits();
const OPENAT2_MODE_MASK: u64 = 0o7777;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub(super) fn sys_creat(path_addr: Vaddr, mode: u16, ctx: &Context) -> Result<SyscallReturn> {
    let flags =
        AccessMode::O_WRONLY as u32 | CreationFlags::O_CREAT.bits() | CreationFlags::O_TRUNC.bits();
    sys_openat(AT_FDCWD, path_addr, flags, mode, ctx)
}

fn do_open(
    path_resolver: &PathResolver,
    fs_path: &FsPath,
    flags: u32,
    mode: InodeMode,
) -> Result<Arc<dyn FileLike>> {
    let open_args = OpenArgs::from_flags_and_mode(flags, mode)?;

    let lookup_res = if open_args.is_tmpfile() {
        LookupResult::Resolved(if open_args.follow_tail_link() {
            path_resolver.lookup(fs_path)?
        } else {
            path_resolver.lookup_no_follow(fs_path)?
        })
    } else if open_args.follow_tail_link() {
        path_resolver.lookup_unresolved(fs_path)?
    } else {
        path_resolver.lookup_unresolved_no_follow(fs_path)?
    };

    do_open_resolved(lookup_res, open_args)
}

fn do_open_resolved(
    lookup_res: LookupResult,
    open_args: OpenArgs,
) -> Result<Arc<dyn FileLike>> {
    if open_args.is_tmpfile() {
        let dir_path = match lookup_res {
            LookupResult::Resolved(path) => path,
            LookupResult::AtParent(_) => {
                return_errno_with_message!(Errno::ENOENT, "the directory does not exist");
            }
        };
        return do_open_tmpfile(&dir_path, &open_args);
    }

    let file_handle: Arc<dyn FileLike> = match lookup_res {
        LookupResult::Resolved(path) => Arc::new(path.open(open_args)?),
        LookupResult::AtParent(result) => {
            if !open_args.creation_flags.contains(CreationFlags::O_CREAT)
                || open_args.status_flags.contains(StatusFlags::O_PATH)
            {
                return_errno_with_message!(Errno::ENOENT, "the file does not exist");
            }
            if result.target_is_dir() {
                return_errno_with_message!(
                    Errno::EISDIR,
                    "O_CREAT is specified but the file is a directory"
                );
            }

            let (parent, tail_name) = result.into_parent_and_basename();
            let new_path = parent.new_child(&tail_name, InodeType::File, open_args.inode_mode)?;
            fs::vfs::notify::on_create(&parent, || tail_name.clone());

            // Don't check access mode for newly created file.
            Arc::new(InodeHandle::new_unchecked_access(
                new_path,
                open_args.access_mode,
                open_args.status_flags,
            )?)
        }
    };

    Ok(file_handle)
}

fn do_open_tmpfile(
    dir_path: &Path,
    open_args: &OpenArgs,
) -> Result<Arc<dyn FileLike>> {
    // `O_EXCL` with `O_TMPFILE` is allowed by Linux, but it prevents the tmpfile
    // from being linked later by `linkat(..., AT_EMPTY_PATH)`.
    // Reference: <https://man7.org/linux/man-pages/man2/open.2.html>.
    let hard_linkability = if open_args.creation_flags.contains(CreationFlags::O_EXCL) {
        HardLinkability::Unlinkable
    } else {
        HardLinkability::Linkable
    };
    let tmpfile_path = dir_path.create_tmpfile(open_args.inode_mode, hard_linkability)?;

    Ok(Arc::new(InodeHandle::new_unchecked_access(
        tmpfile_path,
        open_args.access_mode,
        open_args.status_flags,
    )?))
}
