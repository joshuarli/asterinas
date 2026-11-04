// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;
use crate::{
    fs::{file::{InodeType, mkmod}, procfs::{StaticEntry, template::{
        ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry, listed_entries_from_table,
        lookup_child_from_table, visit_listed_entries,
    }}, vfs::inode::Inode},
    net::socket::ip::{ping_group_range, set_ping_group_range},
    prelude::*,
};

pub(super) struct NetDirOps;
struct Ipv4DirOps;
struct PingGroupRangeFileOps;

impl NetDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { ProcDir::new(Self, parent, mkmod!(a+rx)) }
    const ENTRIES: &'static [StaticEntry] = &[("ipv4", InodeType::Dir, Ipv4DirOps::new_inode)];
}
impl Ipv4DirOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { ProcDir::new(Self, parent, mkmod!(a+rx)) }
    const ENTRIES: &'static [StaticEntry] = &[("ping_group_range", InodeType::File, PingGroupRangeFileOps::new_inode)];
}
macro_rules! proc_dir {
    ($kind:ty) => {
        impl ProcDirOps for $kind {
            fn lookup_child(&self, dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
                lookup_child_from_table(name, Self::ENTRIES, |f| (f)(dir.this_weak().clone()))
                    .ok_or_else(|| Error::from(Errno::ENOENT))
            }
            fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit: F) -> Result<()>
            where F: FnMut(ReaddirEntry<'a>) -> Result<()> {
                visit_listed_entries(offset, listed_entries_from_table(Self::ENTRIES), visit)
            }
        }
    };
}
proc_dir!(NetDirOps);
proc_dir!(Ipv4DirOps);

impl PingGroupRangeFileOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { ProcFile::new(Self, parent, mkmod!(a+r, u+w)) }
}
fn parse_group_id(value: &str) -> Option<u32> {
    if !value.as_bytes().first()?.is_ascii_digit() { return None; }
    let (digits, radix) = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        (hex, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u32::from_str_radix(digits, radix).ok().filter(|value| *value != u32::MAX)
}

impl ProcFileOps for PingGroupRangeFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let (low, high) = ping_group_range();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{}\t{}", low, high)?;
        Ok(printer.bytes_written())
    }
    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (value, read) = reader.read_cstring_until_end(31)?;
        let value = value.to_str().map_err(|_| Errno::EINVAL)?;
        let mut numbers = value.split_whitespace();
        let low = numbers.next().and_then(parse_group_id)
            .ok_or_else(|| Error::from(Errno::EINVAL))?;
        let high = match numbers.next() {
            Some(value) => parse_group_id(value).ok_or_else(|| Error::from(Errno::EINVAL))?,
            None => ping_group_range().1,
        };
        set_ping_group_range(low, high);
        Ok(read)
    }
}
