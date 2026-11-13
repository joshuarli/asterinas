// SPDX-License-Identifier: MPL-2.0

//! Inode metadata operations: mode, ownership, timestamps, and xattr.
//!
//! Ext2 inode metadata includes the file mode, user and group ownership,
//! timestamps, and extended attributes. Attribute mutations must update the
//! relevant change timestamps and mark the inode descriptor dirty so the
//! on-disk inode can be refreshed during writeback.

#![short_vis_path::add(ext2)]

use device_id::DeviceId;

use crate::{
    fs::{
        ext2::{inode::Inode, prelude::*, utils},
        file::InodeMode,
        vfs::{
            inode::Metadata,
            inode_ext::InodeExt,
            posix_acl::{self, AccessAclUpdate, PosixAcl},
            xattr::{XattrName, XattrNamespace, XattrSetFlags},
        },
    },
    process::{Gid, Uid},
};

impl Inode {
    /// Returns the encoded device ID for special files.
    pub(in ext2) fn device_id(&self) -> u64 {
        debug_assert!(self.type_ == InodeType::CharDevice || self.type_ == InodeType::BlockDevice);

        let inner = self.inner.read();
        match &inner.payload {
            super::InodePayload::Device { device_id } => *device_id,
            _ => 0,
        }
    }

    /// Sets the encoded device ID for special files and persists it.
    pub(in ext2) fn set_device_id(&self, device_id: u64) -> Result<()> {
        if self.type_ != InodeType::CharDevice && self.type_ != InodeType::BlockDevice {
            return_errno!(Errno::EINVAL);
        }
        let mut inner = self.inner.write();
        inner.payload = super::InodePayload::Device { device_id };
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// Returns the inode metadata snapshot for stat-like queries.
    pub(in ext2) fn metadata(&self) -> Metadata {
        let inner = self.inner.read();
        let block_meta = inner.raw_block_ptrs();

        let container_dev_id = match self.fs.upgrade() {
            Some(fs) => fs.block_device().id(),
            None => DeviceId::null(),
        };
        let self_dev_id =
            if self.type_ == InodeType::CharDevice || self.type_ == InodeType::BlockDevice {
                DeviceId::from_encoded_u64(block_meta.read_device_id())
            } else {
                None
            };
        Metadata {
            ino: self.ino as u64,
            size: inner.file_size(),
            optimal_block_size: BLOCK_SIZE,
            nr_sectors_allocated: block_meta.sector_count as usize,
            last_access_at: inner.atime(),
            last_modify_at: inner.mtime(),
            last_meta_change_at: inner.ctime(),
            type_: self.type_,
            mode: inner.mode(),
            nr_hard_links: inner.link_count() as usize,
            uid: Uid::new(inner.uid()),
            gid: Gid::new(inner.gid()),
            container_dev_id,
            self_dev_id,
            birth_at: None,
        }
    }

    /// Returns the inode type.
    pub(in ext2) fn inode_type(&self) -> InodeType {
        self.type_
    }

    /// Returns the file permission mode.
    pub(in ext2) fn mode(&self) -> InodeMode {
        let inner = self.inner.read();
        inner.mode()
    }

    /// Sets the file permission mode.
    pub(in ext2) fn set_mode(&self, mode: InodeMode) -> Result<()> {
        let mut inner = self.inner.write();
        inner.set_mode(mode);
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// Returns the owner user ID.
    pub(in ext2) fn uid(&self) -> u32 {
        self.inner.read().uid()
    }

    /// Sets the owner user ID.
    pub(in ext2) fn set_uid(&self, uid: u32) -> Result<()> {
        let mut inner = self.inner.write();
        inner.set_uid(uid);
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// Returns the owner group ID.
    pub(in ext2) fn gid(&self) -> u32 {
        self.inner.read().gid()
    }

    /// Sets the owner group ID.
    pub(in ext2) fn set_gid(&self, gid: u32) -> Result<()> {
        let mut inner = self.inner.write();
        inner.set_gid(gid);
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// Returns the last access time.
    pub(in ext2) fn atime(&self) -> Duration {
        self.inner.read().atime()
    }

    /// Sets the last access time.
    pub(in ext2) fn set_atime(&self, time: Duration) {
        self.inner.write().set_atime(time);
    }

    /// Returns the last data modification time.
    pub(in ext2) fn mtime(&self) -> Duration {
        self.inner.read().mtime()
    }

    /// Sets the last data modification time.
    pub(in ext2) fn set_mtime(&self, time: Duration) {
        self.inner.write().set_mtime(time);
    }

    /// Returns the last metadata change time.
    pub(in ext2) fn ctime(&self) -> Duration {
        self.inner.read().ctime()
    }

    /// Sets the last metadata change time.
    pub(in ext2) fn set_ctime(&self, time: Duration) {
        self.inner.write().set_ctime(time);
    }

    /// Reads one extended-attribute value and writes it to `value_writer`.
    pub(in ext2) fn get_xattr(
        &self,
        name: XattrName,
        value_writer: &mut VmWriter,
    ) -> Result<usize> {
        if posix_acl::is_acl(name.full_name()) {
            let _ownership = self.fs_lock_context_or_init().ownership_lock().lock();
            let acl = self.read_acl(name)?.ok_or_else(|| Error::new(Errno::ENODATA))?;
            let value = acl.encode();
            if value_writer.avail() == 0 {
                return Ok(value.len());
            }
            if value_writer.avail() < value.len() {
                return_errno!(Errno::ERANGE);
            }
            VmReader::from(value.as_slice()).read_fallible(value_writer)?;
            return Ok(value.len());
        }
        let xattr = self.xattr.as_ref().ok_or_else(|| {
            Error::with_message(Errno::ENODATA, "xattr not supported on this inode type")
        })?;
        xattr.get_xattr(name, value_writer)
    }

    /// Lists extended attribute names in one namespace and writes them to `list_writer`.
    pub(in ext2) fn list_xattr(
        &self,
        namespace: XattrNamespace,
        list_writer: &mut VmWriter,
    ) -> Result<usize> {
        let Some(xattr) = self.xattr.as_ref() else {
            return Ok(0);
        };
        xattr.list_xattr(namespace, list_writer)
    }

    /// Creates or replaces one extended attribute.
    pub(in ext2) fn set_xattr(
        &self,
        name: XattrName,
        value_reader: &mut VmReader,
        flags: XattrSetFlags,
    ) -> Result<()> {
        if name.full_name() == posix_acl::DEFAULT {
            return_errno!(Errno::EOPNOTSUPP);
        }
        if name.full_name() == posix_acl::ACCESS {
            let acl = posix_acl::read_user_acl(value_reader)?;
            let _ownership = self.fs_lock_context_or_init().ownership_lock().lock();
            return self.update_access_acl(AccessAclUpdate::set(acl, self.mode()));
        }
        let _ownership = self.fs_lock_context_or_init().ownership_lock().lock();
        let xattr = self.xattr.as_ref().ok_or_else(|| {
            Error::with_message(Errno::EPERM, "xattr not supported on this inode type")
        })?;
        xattr.set_xattr(name, value_reader, flags)?;
        let new_bid = xattr.bid();

        let mut inner = self.inner.write();
        inner.set_file_acl(new_bid);
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// The caller holds the inode ownership lock.
    pub(in ext2) fn read_acl(&self, name: XattrName) -> Result<Option<PosixAcl>> {
        let Some(xattr) = self.xattr.as_ref() else { return Ok(None) };
        let mut empty = [];
        let mut query = VmWriter::from(empty.as_mut_slice()).to_fallible();
        let length = match xattr.get_xattr(name, &mut query) {
            Ok(length) => length,
            Err(error) if error.error() == Errno::ENODATA => return Ok(None),
            Err(error) => return Err(error),
        };
        if length > BLOCK_SIZE {
            return_errno!(Errno::EIO);
        }
        let mut value = vec![0; length];
        let mut writer = VmWriter::from(value.as_mut_slice()).to_fallible();
        if xattr.get_xattr(name, &mut writer)? != length {
            return_errno!(Errno::EIO);
        }
        decode_disk_acl(&value)
    }

    pub(in ext2) fn update_access_acl(&self, update: AccessAclUpdate) -> Result<()> {
        let xattr = self.xattr.as_ref().ok_or_else(|| Error::new(Errno::EOPNOTSUPP))?;
        let name = XattrName::try_from_full_name(posix_acl::ACCESS).unwrap();
        if let Some(value) = update.value() {
            let value = encode_disk_acl(value);
            let mut reader = VmReader::from(value.as_slice()).to_fallible();
            xattr.set_xattr(name, &mut reader, XattrSetFlags::CREATE_OR_REPLACE)?;
        } else {
            match xattr.remove_xattr(name) {
                Ok(()) => {},
                Err(error) if error.error() == Errno::ENODATA => {},
                Err(error) => return Err(error),
            }
        }
        let new_bid = xattr.bid();
        let mut inner = self.inner.write();
        inner.set_file_acl(new_bid);
        inner.set_mode(update.mode());
        inner.set_ctime(utils::now());
        Ok(())
    }

    /// Removes one extended attribute.
    pub(in ext2) fn remove_xattr(&self, name: XattrName) -> Result<()> {
        let _ownership = self.fs_lock_context_or_init().ownership_lock().lock();
        let xattr = self.xattr.as_ref().ok_or_else(|| {
            Error::with_message(Errno::EPERM, "xattr not supported on this inode type")
        })?;
        xattr.remove_xattr(name)?;
        let new_bid = xattr.bid();

        let mut inner = self.inner.write();
        inner.set_file_acl(new_bid);
        inner.set_ctime(utils::now());
        Ok(())
    }
}

fn encode_disk_acl(wire: &[u8]) -> Vec<u8> {
    let mut disk = Vec::with_capacity(wire.len());
    disk.extend_from_slice(&1u32.to_le_bytes());
    for entry in wire[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        disk.extend_from_slice(&entry[..if matches!(tag, 2 | 8) { 8 } else { 4 }]);
    }
    disk
}

fn decode_disk_acl(disk: &[u8]) -> Result<Option<PosixAcl>> {
    if disk.len() < 4 || u32::from_le_bytes(disk[..4].try_into().unwrap()) != 1 {
        return_errno_with_message!(Errno::EIO, "invalid ext2 ACL header");
    }
    let mut wire = Vec::with_capacity(disk.len() * 2);
    wire.extend_from_slice(&2u32.to_le_bytes());
    let mut offset = 4;
    while offset < disk.len() {
        let entry = disk.get(offset..offset + 4).ok_or_else(|| Error::new(Errno::EIO))?;
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        wire.extend_from_slice(entry);
        offset += 4;
        match tag {
            1 | 4 | 16 | 32 => wire.extend_from_slice(&u32::MAX.to_le_bytes()),
            2 | 8 => {
                wire.extend_from_slice(disk.get(offset..offset + 4)
                    .ok_or_else(|| Error::new(Errno::EIO))?);
                offset += 4;
            }
            _ => return_errno!(Errno::EIO),
        }
    }
    PosixAcl::decode(&wire).map_err(|_| Error::with_message(Errno::EIO, "invalid ext2 ACL entries"))
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;
    use crate::fs::ext2::{
        inode::test::read_raw_inode_from_disk,
        test_utils::{create_file, default_fixture},
    };

    const BLOCK_SECTORS: u32 = (BLOCK_SIZE / SECTOR_SIZE) as u32;

    #[ktest]
    fn xattr_block_is_counted_in_i_blocks() {
        let (f, root) = default_fixture();
        let file = create_file(&root, "file");
        let data = vec![0x5au8; BLOCK_SIZE];
        file.write_direct_at(0, &mut VmReader::from(data.as_slice()).to_fallible())
            .unwrap();
        let name = XattrName::try_from_full_name("user.mime").unwrap();
        file.set_xattr(
            name,
            &mut VmReader::from(b"text/plain".as_slice()).to_fallible(),
            XattrSetFlags::CREATE_OR_REPLACE,
        )
        .unwrap();
        f.ext2.sync_all().unwrap();
        let raw = read_raw_inode_from_disk(&f, file.ino());
        assert_ne!(raw.file_acl, 0);
        assert_eq!(raw.sector_count, 2 * BLOCK_SECTORS);
        assert_eq!(file.metadata().nr_sectors_allocated, 2 * BLOCK_SECTORS as usize);

        file.write_direct_at(BLOCK_SIZE, &mut VmReader::from(data.as_slice()).to_fallible())
            .unwrap();
        f.ext2.sync_all().unwrap();
        assert_eq!(read_raw_inode_from_disk(&f, file.ino()).sector_count, 3 * BLOCK_SECTORS);

        file.remove_xattr(name).unwrap();
        f.ext2.sync_all().unwrap();
        let raw = read_raw_inode_from_disk(&f, file.ino());
        assert_eq!(raw.file_acl, 0);
        assert_eq!(raw.sector_count, 2 * BLOCK_SECTORS);
    }
}
