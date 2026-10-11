// SPDX-License-Identifier: MPL-2.0

#![expect(unused_variables)]

use crate::{fs::file::InodeType, prelude::*};

/// A visitor for dir entries.
pub trait DirentVisitor {
    /// Visit a dir entry.
    ///
    /// If the visitor succeeds in visiting the given inode, an `Ok(())` is returned;
    /// Otherwise, an error is returned. Different implementations for `DirentVisitor`
    /// may choose to report errors for different reasons. Regardless of the exact
    /// errors and reasons, `readdir`-family methods shall stop feeding the visitor
    /// with the next inode as long as an error is returned by the visitor.
    ///
    /// # Example
    ///
    /// `Vec<String>` is implemented as `DirentVisitor` so that the file names
    /// under a dir can be easily collected, which is convenient for testing purposes.
    ///
    /// ```no_run
    /// let mut all_dirents = Vec::new();
    /// let dir_inode = todo!("create an inode");
    /// dir_inode.readdir_at(0, &mut all_dirents).unwrap();
    /// ```
    fn visit(&mut self, name: &str, ino: u64, type_: InodeType, offset: usize) -> Result<()>;

    /// Visit a directory entry whose name is an arbitrary Linux pathname byte sequence.
    ///
    /// Implementations that expose names as text keep working for UTF-8 names; visitors that
    /// implement the syscall ABI can override this method to preserve every byte.
    fn visit_bytes(&mut self, name: &[u8], ino: u64, type_: InodeType, offset: usize) -> Result<()> {
        let name = core::str::from_utf8(name)
            .map_err(|_| Error::with_message(Errno::EILSEQ, "directory entry name is not UTF-8"))?;
        self.visit(name, ino, type_, offset)
    }
}

impl DirentVisitor for Vec<String> {
    fn visit(&mut self, name: &str, ino: u64, type_: InodeType, offset: usize) -> Result<()> {
        self.push(name.into());
        Ok(())
    }
}
