// SPDX-License-Identifier: MPL-2.0

use super::{inode::Inode, xattr::{XATTR_VALUE_MAX_LEN, XattrName}};
use crate::{fs::file::InodeMode, prelude::*, process::{Gid, Uid}};

pub(crate) const ACCESS: &str = "system.posix_acl_access";
pub(crate) const DEFAULT: &str = "system.posix_acl_default";

pub(crate) fn is_acl(name: &str) -> bool {
    matches!(name, ACCESS | DEFAULT)
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Owner(u8),
    User(Uid, u8),
    OwningGroup(u8),
    Group(Gid, u8),
    Mask(u8),
    Other(u8),
}

#[derive(Clone, Debug)]
pub(crate) struct PosixAcl {
    entries: Vec<Entry>,
}

#[derive(Clone, Copy)]
enum Phase {
    Owner,
    Users,
    Groups,
    Other,
    End,
}

impl PosixAcl {
    pub(crate) fn decode(data: &[u8]) -> Result<Option<Self>> {
        if data.is_empty() {
            return Ok(None);
        }
        if data.len() < 4 || (data.len() - 4) % 8 != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid POSIX ACL size");
        }
        if u32::from_le_bytes(data[..4].try_into().unwrap()) != 2 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported POSIX ACL version");
        }
        if data.len() == 4 {
            return Ok(None);
        }
        let mut phase = Phase::Owner;
        let mut needs_mask = false;
        let mut entries = Vec::with_capacity((data.len() - 4) / 8);
        for raw in data[4..].chunks_exact(8) {
            let tag = u16::from_le_bytes(raw[..2].try_into().unwrap());
            let permissions = u16::from_le_bytes(raw[2..4].try_into().unwrap());
            let id = u32::from_le_bytes(raw[4..8].try_into().unwrap());
            if permissions > 7 {
                return_errno_with_message!(Errno::EINVAL, "invalid POSIX ACL permissions");
            }
            let permissions = permissions as u8;
            let entry = match (phase, tag) {
                (Phase::Owner, 1) => {
                    phase = Phase::Users;
                    Entry::Owner(permissions)
                }
                (Phase::Users, 2) if id != u32::MAX => {
                    needs_mask = true;
                    Entry::User(Uid::new(id), permissions)
                }
                (Phase::Users, 4) => {
                    phase = Phase::Groups;
                    Entry::OwningGroup(permissions)
                }
                (Phase::Groups, 8) if id != u32::MAX => {
                    needs_mask = true;
                    Entry::Group(Gid::new(id), permissions)
                }
                (Phase::Groups, 16) => {
                    phase = Phase::Other;
                    Entry::Mask(permissions)
                }
                (Phase::Other, 32) | (Phase::Groups, 32) if !needs_mask || matches!(phase, Phase::Other) => {
                    phase = Phase::End;
                    Entry::Other(permissions)
                }
                _ => return_errno_with_message!(Errno::EINVAL, "invalid POSIX ACL entry order"),
            };
            entries.push(entry);
        }
        if !matches!(phase, Phase::End) {
            return_errno_with_message!(Errno::EINVAL, "incomplete POSIX ACL");
        }
        Ok(Some(Self { entries }))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + self.entries.len() * 8);
        data.extend_from_slice(&2u32.to_le_bytes());
        for entry in &self.entries {
            let (tag, permissions, id): (u16, u8, u32) = match *entry {
                Entry::Owner(p) => (1, p, u32::MAX),
                Entry::User(id, p) => (2, p, id.into()),
                Entry::OwningGroup(p) => (4, p, u32::MAX),
                Entry::Group(id, p) => (8, p, id.into()),
                Entry::Mask(p) => (16, p, u32::MAX),
                Entry::Other(p) => (32, p, u32::MAX),
            };
            data.extend_from_slice(&tag.to_le_bytes());
            data.extend_from_slice(&(permissions as u16).to_le_bytes());
            data.extend_from_slice(&id.to_le_bytes());
        }
        data
    }

    fn mode(&self, previous: InodeMode) -> InodeMode {
        let mut permissions = 0u16;
        for entry in &self.entries {
            match *entry {
                Entry::Owner(p) => permissions |= (p as u16) << 6,
                Entry::OwningGroup(p) => permissions |= (p as u16) << 3,
                Entry::Mask(p) => permissions = (permissions & !0o070) | ((p as u16) << 3),
                Entry::Other(p) => permissions |= p as u16,
                _ => {}
            }
        }
        InodeMode::from_bits_truncate((previous.bits() & !0o777) | permissions)
    }

    fn chmod(&mut self, mode: InodeMode) {
        let masked = self.entries.iter().any(|entry| matches!(entry, Entry::Mask(_)));
        for entry in &mut self.entries {
            match entry {
                Entry::Owner(p) => *p = ((mode.bits() >> 6) & 7) as u8,
                Entry::OwningGroup(p) if !masked => *p = ((mode.bits() >> 3) & 7) as u8,
                Entry::Mask(p) => *p = ((mode.bits() >> 3) & 7) as u8,
                Entry::Other(p) => *p = (mode.bits() & 7) as u8,
                _ => {}
            }
        }
    }

    /// Masks an inherited default ACL and the requested creation mode by each other.
    ///
    /// Returns the resulting mode and whether the ACL carries entries beyond the mode bits.
    /// Reference: Linux `posix_acl_create_masq` in `fs/posix_acl.c`.
    pub(crate) fn create_masq(&mut self, mode: InodeMode) -> (InodeMode, bool) {
        let mut bits = mode.bits();
        let mut extended = false;
        let mut group_index = None;
        let mut mask_index = None;
        for (index, entry) in self.entries.iter_mut().enumerate() {
            match entry {
                Entry::Owner(p) => {
                    *p &= ((bits >> 6) & 7) as u8;
                    bits &= ((*p as u16) << 6) | !0o700;
                }
                Entry::User(..) | Entry::Group(..) => extended = true,
                Entry::OwningGroup(_) => group_index = Some(index),
                Entry::Mask(_) => {
                    mask_index = Some(index);
                    extended = true;
                }
                Entry::Other(p) => {
                    *p &= (bits & 7) as u8;
                    bits &= (*p as u16) | !0o007;
                }
            }
        }
        if let Some(index) = mask_index.or(group_index)
            && let Entry::Mask(p) | Entry::OwningGroup(p) = &mut self.entries[index]
        {
            *p &= ((bits >> 3) & 7) as u8;
            bits &= ((*p as u16) << 3) | !0o070;
        }
        (InodeMode::from_bits_truncate(bits), extended)
    }

    pub(crate) fn permits(&self, uid: Uid, owner: Uid, owning_group: Gid,
        mut in_group: impl FnMut(Gid) -> bool, wanted: u8) -> bool {
        let mask = self.entries.iter().find_map(|entry| match entry {
            Entry::Mask(p) => Some(*p),
            _ => None,
        }).unwrap_or(7);
        let mut matched_group = false;
        for entry in &self.entries {
            match *entry {
                Entry::Owner(p) if uid == owner => return p & wanted == wanted,
                Entry::User(id, p) if uid == id => return p & mask & wanted == wanted,
                Entry::OwningGroup(p) if in_group(owning_group) => {
                    matched_group = true;
                    if p & wanted == wanted {
                        return p & mask & wanted == wanted;
                    }
                }
                Entry::Group(id, p) if in_group(id) => {
                    matched_group = true;
                    if p & wanted == wanted {
                        return p & mask & wanted == wanted;
                    }
                }
                Entry::Other(p) => return !matched_group && p & wanted == wanted,
                _ => {}
            }
        }
        false
    }
}

pub(crate) struct AccessAclUpdate {
    value: Option<Vec<u8>>,
    mode: InodeMode,
}

impl AccessAclUpdate {
    pub(crate) fn set(acl: Option<PosixAcl>, previous: InodeMode) -> Self {
        let mode = acl.as_ref().map_or(previous, |acl| acl.mode(previous));
        let value = acl.filter(|acl| acl.entries.len() != 3).map(|acl| acl.encode());
        Self { value, mode }
    }

    pub(crate) fn chmod(mut acl: PosixAcl, mode: InodeMode) -> Self {
        acl.chmod(mode);
        Self::set(Some(acl), mode)
    }

    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    pub(crate) fn mode(&self) -> InodeMode {
        self.mode
    }

    pub(crate) fn clear_setgid(&mut self) {
        self.mode.remove(InodeMode::S_ISGID);
    }
}

pub(crate) fn read_user_acl(reader: &mut VmReader) -> Result<Option<PosixAcl>> {
    if reader.remain() > XATTR_VALUE_MAX_LEN {
        return_errno!(Errno::E2BIG);
    }
    let mut bytes = vec![0; reader.remain()];
    reader.read_fallible(&mut VmWriter::from(bytes.as_mut_slice()))?;
    PosixAcl::decode(&bytes)
}

/// The caller holds the inode ownership lock across both raw xattr reads.
pub(crate) fn read_stored_acl(inode: &dyn Inode) -> Result<Option<PosixAcl>> {
    let name = XattrName::try_from_full_name(ACCESS).unwrap();
    let mut empty = [];
    let mut query = VmWriter::from(empty.as_mut_slice()).to_fallible();
    let length = match inode.get_xattr(name, &mut query) {
        Ok(length) => length,
        Err(error) if matches!(error.error(), Errno::ENODATA | Errno::EOPNOTSUPP) => return Ok(None),
        Err(error) => return Err(error),
    };
    if length > XATTR_VALUE_MAX_LEN {
        return_errno_with_message!(Errno::EIO, "stored POSIX ACL exceeds the attribute limit");
    }
    let mut bytes = vec![0; length];
    let mut writer = VmWriter::from(bytes.as_mut_slice()).to_fallible();
    let actual = inode.get_xattr(name, &mut writer)?;
    if actual != length {
        return_errno_with_message!(Errno::EIO, "stored POSIX ACL changed during a locked read");
    }
    PosixAcl::decode(&bytes)
}

/// Reads a directory's stored default ACL in one attribute read.
pub(crate) fn read_default_acl(inode: &dyn Inode) -> Result<Option<PosixAcl>> {
    let name = XattrName::try_from_full_name(DEFAULT).unwrap();
    let mut capacity = 4 + 8 * 32;
    loop {
        let mut bytes = vec![0; capacity];
        let mut writer = VmWriter::from(bytes.as_mut_slice()).to_fallible();
        match inode.get_xattr(name, &mut writer) {
            Ok(length) => {
                bytes.truncate(length);
                return PosixAcl::decode(&bytes);
            }
            Err(error) if matches!(error.error(), Errno::ENODATA | Errno::EOPNOTSUPP) => return Ok(None),
            Err(error) if error.error() == Errno::ERANGE && capacity < XATTR_VALUE_MAX_LEN => {
                capacity = XATTR_VALUE_MAX_LEN;
            }
            Err(error) => return Err(error),
        }
    }
}
