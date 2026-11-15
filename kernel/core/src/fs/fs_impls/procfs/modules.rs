// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

pub(super) struct ModulesFileOps;

impl ModulesFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for ModulesFileOps {
    fn read_at(&self, _offset: usize, _writer: &mut VmWriter) -> Result<usize> {
        Ok(0)
    }
}
