// SPDX-License-Identifier: MPL-2.0

//! Options for allocating root and child VMOs.

use core::sync::atomic::AtomicUsize;

use align_ext::AlignExt;
use ostd::mm::{FrameAllocOptions, Segment};
use xarray::XArray;

use super::{Vmo, VmoFlags, WritableMappingStatus};
use crate::{
    prelude::*,
    vm::{
        page_cache::{CachePage, CachePageMeta, PageCacheBackend, PageKind, cache_page::PageState},
        vmar::Rmap,
    },
};

/// Options for allocating a root VMO.
///
/// # Examples
///
/// Creating a generic VMO:
/// ```
/// use ostd::mm::PAGE_SIZE;
///
/// use crate::vm::page_cache::VmoOptions;
///
/// let vmo = VmoOptions::new(PAGE_SIZE).alloc();
/// assert!(vmo.is_ok());
/// ```
///
/// Creating an anonymous page-cache-style VMO:
/// ```
/// use ostd::mm::PAGE_SIZE;
///
/// use crate::vm::page_cache::VmoOptions;
///
/// let vmo = VmoOptions::new_anon(10 * PAGE_SIZE).alloc();
/// assert!(vmo.is_ok());
/// ```
pub(crate) struct VmoOptions {
    size: usize,
    kind: PageKind,
    flags: VmoFlags,
    backend: Option<Weak<dyn PageCacheBackend>>,
}

impl VmoOptions {
    /// Creates a default set of options with the specified size of the VMO
    /// (in bytes).
    ///
    /// The size of the VMO will be rounded up to align with the page size.
    ///
    /// This is the low-level builder entry point. Call [`VmoOptions::new_anon`]
    /// for resizable RAM-backed page-cache-style VMOs, or
    /// [`VmoOptions::new_page_cache`] for page-cache VMOs with a backend.
    pub(crate) fn new(size: usize) -> Self {
        Self {
            size,
            kind: PageKind::Anonymous,
            flags: VmoFlags::empty(),
            backend: None,
        }
    }

    /// Creates options for an anonymous resizable VMO.
    pub(crate) fn new_anon(size: usize) -> Self {
        Self::new(size)
            .kind(PageKind::FileCache)
            .flags(VmoFlags::RESIZABLE)
    }

    /// Creates options for a page-cache VMO with a backend.
    pub(crate) fn new_page_cache(size: usize, backend: Weak<dyn PageCacheBackend>) -> Self {
        Self::new(size)
            .kind(PageKind::FileCache)
            .flags(VmoFlags::RESIZABLE)
            .backend(backend)
    }

    pub(crate) fn new_shared(size: usize) -> Self {
        Self::new(size).kind(PageKind::Shared)
    }

    fn kind(mut self, kind: PageKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the VMO flags.
    ///
    /// The default value is `VmoFlags::empty()`.
    ///
    /// For more information about the flags, see `VmoFlags`.
    pub(crate) fn flags(mut self, flags: VmoFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the backend for the VMO.
    fn backend(mut self, backend: Weak<dyn PageCacheBackend>) -> Self {
        self.backend = Some(backend);
        self
    }
}

impl VmoOptions {
    /// Allocates the VMO according to the specified options.
    pub(crate) fn alloc(self) -> Result<Arc<Vmo>> {
        let VmoOptions {
            size,
            flags,
            backend,
            kind,
        } = self;
        let vmo = alloc_vmo(size, flags, backend, kind)?;
        Ok(Arc::new(vmo))
    }
}

fn alloc_vmo(
    size: usize,
    flags: VmoFlags,
    backend: Option<Weak<dyn PageCacheBackend>>,
    kind: PageKind,
) -> Result<Vmo> {
    let size = size.align_up(PAGE_SIZE);
    let pages = committed_pages_if_continuous(flags, size, kind)?;
    let writable_mapping_status = WritableMappingStatus::default();
    let rmap = Rmap::new();
    Ok(Vmo {
        backend,
        flags,
        kind,
        pages,
        size: AtomicUsize::new(size),
        writable_mapping_status,
        rmap: Mutex::new(rmap),
    })
}

fn committed_pages_if_continuous(
    flags: VmoFlags,
    size: usize,
    kind: PageKind,
) -> Result<XArray<CachePage>> {
    if flags.contains(VmoFlags::CONTIGUOUS) {
        // if the vmo is continuous, we need to allocate frames for the vmo
        let frames_num = size / PAGE_SIZE;
        let segment: Segment<CachePageMeta> = FrameAllocOptions::new()
            .alloc_segment_with(frames_num, |_| CachePageMeta::new(kind, PageState::Uninit))?;
        let committed_pages = XArray::new();
        let mut locked_pages = committed_pages.lock();
        let mut cursor = locked_pages.cursor_mut(0);
        for frame in segment {
            cursor.store(frame);
            cursor.next();
        }
        drop(locked_pages);
        Ok(committed_pages)
    } else {
        // otherwise, we wait for the page is read or write
        Ok(XArray::new())
    }
}

#[cfg(ktest)]
mod test {
    use ostd::{mm::VmIo, prelude::*};

    use super::*;

    #[ktest]
    fn resident_page_lifetime() {
        use crate::vm::page_cache::{CachePageExt, PageCache, resident_page_counts};

        assert_eq!(VmoOptions::new(PAGE_SIZE).kind, PageKind::Anonymous);
        assert_eq!(VmoOptions::new_anon(PAGE_SIZE).kind, PageKind::FileCache);
        assert_eq!(VmoOptions::new_shared(PAGE_SIZE).kind, PageKind::Shared);
        let before = resident_page_counts();
        let page = CachePage::alloc_zero(PageKind::Shared).unwrap();
        assert_eq!(resident_page_counts(), (before.0, before.1 + 1));
        let clone = page.clone();
        drop(page);
        assert_eq!(resident_page_counts(), (before.0, before.1 + 1));
        drop(clone);
        assert_eq!(resident_page_counts(), before);

        let file = CachePage::alloc_zero(PageKind::FileCache).unwrap();
        assert_eq!(resident_page_counts(), (before.0 + 1, before.1));
        drop(file);
        let anonymous = CachePage::alloc_zero(PageKind::Anonymous).unwrap();
        assert_eq!(resident_page_counts(), before);
        drop(anonymous);
        assert!(committed_pages_if_continuous(VmoFlags::CONTIGUOUS, 0, PageKind::Shared).is_err());
        assert_eq!(resident_page_counts(), before);

        let mut cache = PageCache::new_shared(PAGE_SIZE).unwrap();
        let retained = cache.as_vmo().commit_on_anonymous(0).unwrap();
        cache.resize(0, PAGE_SIZE).unwrap();
        drop(cache);
        assert_eq!(resident_page_counts(), (before.0, before.1 + 1));
        let mut byte = [0xff];
        retained.read(0, &mut VmWriter::from(byte.as_mut_slice()).to_fallible()).unwrap();
        assert_eq!(byte, [0]);
        drop(retained);
    }

    #[ktest]
    fn alloc_vmo() {
        let vmo = VmoOptions::new(PAGE_SIZE).alloc().unwrap();
        assert_eq!(vmo.size(), PAGE_SIZE);
        // the vmo is zeroed once allocated
        let mut read_buffer = [0; size_of::<usize>()];
        let mut writer = VmWriter::from(read_buffer.as_mut_slice()).to_fallible();
        vmo.read(0, &mut writer).unwrap();
        assert_eq!(usize::from_ne_bytes(read_buffer), 0);
    }

    #[ktest]
    fn alloc_continuous_vmo() {
        let vmo = VmoOptions::new(10 * PAGE_SIZE)
            .flags(VmoFlags::CONTIGUOUS)
            .alloc()
            .unwrap();
        assert_eq!(vmo.size(), 10 * PAGE_SIZE);
    }

    #[ktest]
    fn write_and_read() {
        let vmo = VmoOptions::new(PAGE_SIZE).alloc().unwrap();
        let val = 42u8;
        // write val
        let mut reader = VmReader::from(core::slice::from_ref(&val)).to_fallible();
        vmo.write(111, &mut reader).unwrap();

        let mut read_buffer = [0];
        let mut writer = VmWriter::from(read_buffer.as_mut_slice()).to_fallible();
        vmo.read(111, &mut writer).unwrap();
        let read_val = read_buffer[0];
        assert_eq!(val, read_val);
        // bit endian
        let mut reader = VmReader::from(&[0x12, 0x34, 0x56, 0x78][..]).to_fallible();
        vmo.write(222, &mut reader).unwrap();

        let mut read_buffer = [0; size_of::<u32>()];
        let mut writer = VmWriter::from(read_buffer.as_mut_slice()).to_fallible();
        vmo.read(222, &mut writer).unwrap();
        let read_val = u32::from_ne_bytes(read_buffer);
        assert_eq!(read_val, 0x78563412)
    }

    #[ktest]
    fn resize() {
        use crate::vm::page_cache::PageCache;

        let mut page_cache = PageCache::new_anon(PAGE_SIZE).unwrap();
        page_cache.write_val(10, &42u8).unwrap();
        page_cache.resize(2 * PAGE_SIZE, page_cache.size()).unwrap();
        assert_eq!(page_cache.size(), 2 * PAGE_SIZE);
        assert_eq!(page_cache.read_val::<u8>(10).unwrap(), 42);
        page_cache.write_val(PAGE_SIZE + 20, &123u8).unwrap();
        page_cache.resize(PAGE_SIZE, page_cache.size()).unwrap();
        assert_eq!(page_cache.read_val::<u8>(10).unwrap(), 42);
    }
}
