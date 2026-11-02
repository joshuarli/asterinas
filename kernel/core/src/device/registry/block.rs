// SPDX-License-Identifier: MPL-2.0

use alloc::{borrow::ToOwned, format, string::ToString};
use core::sync::atomic::{AtomicU64, Ordering};

use aster_block::{BLOCK_SIZE, BlockDevice, SECTOR_SIZE, bio::BioStatus};
use aster_device::{
    bus::{self, Bus, BusDevice, BusHandle},
    class::{self, Class, ClassDevice, ClassHandle},
    common::{AnyDevice, Attr, BareDevice, DevNum, DeviceType as ModelDeviceType},
};
use aster_nvme::NvmeBlockDevice;
use aster_virtio::{
    VirtioIdentity, VirtioPlacement, device::block::device::BlockDevice as VirtIoBlockDevice,
};
use device_id::DeviceId;
use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType},
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, SettableStatusFlags, StatusFlags, SyncMode},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    thread::kernel_thread::ThreadOptions,
    util::ioctl::RawIoctl,
};

pub(super) fn init_in_first_kthread() {
    for device in aster_block::collect_all() {
        if device.is_partition() {
            continue;
        }

        // Spawn threads for virtio block devices
        if device.downcast_ref::<VirtIoBlockDevice>().is_some() {
            let device_clone = device.clone();
            let task_fn = move || {
                info!("spawn the virtio-block thread");
                let virtio_block_device = device_clone.downcast_ref::<VirtIoBlockDevice>().unwrap();
                loop {
                    virtio_block_device.handle_requests();
                }
            };
            ThreadOptions::new(task_fn).spawn();
        }
        // Spawn threads for NVMe block devices
        else if device.downcast_ref::<NvmeBlockDevice>().is_some() {
            let device_clone = device.clone();
            let task_fn = move || {
                info!("spawn the nvme-block thread");
                let nvme_block_device = device_clone.downcast_ref::<NvmeBlockDevice>().unwrap();
                loop {
                    nvme_block_device.handle_requests();
                }
            };
            ThreadOptions::new(task_fn).spawn();
        }
    }

    // Partition scanning performs synchronous block I/O, so the request
    // handling threads above must be available first.
    aster_block::scan_partitions();
}

pub(super) fn init_in_first_process() -> Result<()> {
    let class = BLOCK_CLASS.call_once(|| class::register(BlockClass).unwrap());
    let devices = aster_block::collect_all();

    let mut disks = Vec::new();
    for device in devices.iter().filter(|device| !device.is_partition()) {
        let entry = BlockEntry {
            device: device.clone(),
            disk_sequence: NEXT_DISK_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        };
        let mut builder = ClassDevice::builder(class, device.name().to_owned(), entry)
            .devnum(DevNum::block(device.id()))
            .dev_type(&DISK_TYPE);
        if let Some(virtio_disk) = device.downcast_ref::<VirtIoBlockDevice>() {
            builder = builder.parent(virtio_parent(virtio_disk.identity())?);
        }
        let disk = builder.build();
        aster_device::add_device(&disk)?;
        disks.push(disk);
    }

    for device in devices.iter().filter(|device| device.is_partition()) {
        let owner = device.partition_disk().and_then(|whole| {
            disks
                .iter()
                .find(|disk| disk.payload().device.id() == whole.id())
        });
        let entry = BlockEntry {
            device: device.clone(),
            disk_sequence: owner.map_or(0, |disk| disk.payload().disk_sequence),
        };
        let mut builder = ClassDevice::builder(class, device.name().to_owned(), entry)
            .devnum(DevNum::block(device.id()))
            .dev_type(&PARTITION_TYPE);
        if let Some(disk) = owner {
            builder = builder.parent(disk.clone());
        }
        aster_device::add_device(&builder.build())?;
    }

    Ok(())
}

/// A block device in the `block` class, with what its uevents report beyond the device itself.
struct BlockEntry {
    device: Arc<dyn BlockDevice>,
    /// The sequence number of the whole disk, which its partitions share.
    disk_sequence: u64,
}

static NEXT_DISK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The `virtio` bus: the devices that a virtio transport carries.
struct VirtioBus;

impl Bus for VirtioBus {
    const NAME: &'static str = "virtio";
    type Device = VirtioIdentity;
    type MatchData = ();

    fn matches(&self, _device: &VirtioIdentity, _driver: &()) -> bool {
        false
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
}

static VIRTIO_BUS: spin::Once<Arc<BusHandle<VirtioBus>>> = spin::Once::new();

/// The devices above the virtio devices that were added already, by their name.
static TRANSPORT_DEVICES: Mutex<BTreeMap<String, Arc<BareDevice>>> = Mutex::new(BTreeMap::new());

/// Adds the devices a virtio block device sits below and returns its `virtioN` device.
///
/// The path follows Linux: a PCI function below its root bus, or a memory-mapped transport
/// below the root of the devices the kernel command line declares.
fn virtio_parent(identity: &VirtioIdentity) -> Result<Arc<dyn AnyDevice>> {
    let transport = match identity.placement {
        VirtioPlacement::Mmio { ordinal, .. } => {
            let root = transport_device("virtio-mmio-cmdline".to_owned(), None)?;
            transport_device(format!("virtio-mmio.{ordinal}"), Some(root))?
        }
        VirtioPlacement::Pci {
            bus,
            device,
            function,
        } => {
            let root = transport_device(format!("pci0000:{bus:02x}"), None)?;
            transport_device(format!("0000:{bus:02x}:{device:02x}.{function}"), Some(root))?
        }
    };

    let bus = VIRTIO_BUS.call_once(|| bus::register(VirtioBus).unwrap());
    let virtio = BusDevice::builder(bus, format!("virtio{}", identity.index), *identity)
        .parent(transport)
        .build();
    aster_device::add_device(&virtio)?;
    Ok(virtio)
}

fn transport_device(name: String, parent: Option<Arc<BareDevice>>) -> Result<Arc<BareDevice>> {
    let mut devices = TRANSPORT_DEVICES.lock();
    if let Some(device) = devices.get(&name) {
        return Ok(device.clone());
    }
    let device = match parent {
        Some(parent) => BareDevice::with_parent(name.clone(), parent),
        None => BareDevice::new_root(name.clone()),
    };
    aster_device::add_device(&device)?;
    devices.insert(name, device.clone());
    Ok(device)
}

/// The `block` class: whole disks and their partitions.
struct BlockClass;

impl Class for BlockClass {
    const NAME: &'static str = "block";
    type Device = BlockEntry;

    fn uevent_environment(&self, dev: &ClassDevice<Self>) -> Vec<(String, String)> {
        let entry = dev.payload();
        let mut environment = vec![("DISKSEQ".to_owned(), entry.disk_sequence.to_string())];
        if let Some(number) = entry.device.partition_number() {
            environment.push(("PARTN".to_owned(), number.to_string()));
        }
        if let Some(uuid) = entry.device.partition_uuid() {
            environment.push(("PARTUUID".to_owned(), uuid));
        }
        environment
    }

    fn dev_attrs(&self) -> &'static [Attr<ClassDevice<Self>>] {
        &[]
    }
}

static BLOCK_CLASS: spin::Once<Arc<ClassHandle<BlockClass>>> = spin::Once::new();

static DISK_TYPE: ModelDeviceType<ClassDevice<BlockClass>> = ModelDeviceType::named("disk");

static PARTITION_TYPE: ModelDeviceType<ClassDevice<BlockClass>> = ModelDeviceType {
    name: "partition",
    attrs: &[Attr::ro("partition", show_partition_number)],
    devnode: None,
    has_device_link: true,
};

fn show_partition_number(
    dev: &ClassDevice<BlockClass>,
    writer: &mut dyn core::fmt::Write,
) -> aster_device::common::Result<()> {
    writeln!(writer, "{}", dev.payload().device.partition_number().unwrap_or(0))?;
    Ok(())
}

mod ioctl_defs {
    use crate::{
        ioc,
        util::ioctl::{NoData, OutData},
    };

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/fs.h>

    /// Returns the device size in bytes.
    pub(super) type BlkGetSize64 = ioc!(BLKGETSIZE64, 0x12, 114, OutData<u64>);

    /// Returns the logical sector size of the block device.
    ///
    /// This is the smallest unit of I/O the device can address and,
    /// importantly, the minimum alignment required for `O_DIRECT` I/O on
    /// files backed by this device. Both buffer address and offset must be a
    /// multiple of this value.
    ///
    /// Benchmarks and filesystem tests (for example, `xfstests`, LTP
    /// `preadv03`/`pwritev03`) rely on this ioctl to size `O_DIRECT` buffers.
    /// If the effective alignment enforced by the filesystem layered on top
    /// is larger than the hardware sector, such as `ext2`'s 4 KiB block, this
    /// ioctl must return that larger value. Otherwise user programs will align
    /// correctly for the device but still hit `EINVAL` at the filesystem.
    pub(super) type BlkGetSectorSize = ioc!(BLKSSZGET, 0x12, 104, NoData);
}

/// Represents a block device inode in the filesystem.
//
// TODO: This type wraps an `Arc<dyn BlockDevice>` in another `Arc` just to implement the `Device`
// trait. It leads to redundant vtable dispatch, reference counting, and heap allocation. We should
// devise a better strategy to eliminate the unnecessary intermediate `Arc`.
#[derive(Debug)]
struct BlockFile(Arc<dyn BlockDevice>);

impl BlockFile {
    fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self(device)
    }
}

impl Device for BlockFile {
    fn type_(&self) -> DeviceType {
        DeviceType::Block
    }

    fn id(&self) -> DeviceId {
        self.0.id()
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        None
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(OpenBlockFile(self.0.clone())))
    }
}

/// Represents an opened block device file ready for I/O operations.
//
// TODO: This type wraps an `Arc<dyn BlockDevice>` in another `Box` just to implement the
// `PerOpenFileOps` trait. It leads to redundant vtable dispatch and heap allocation. We should
// devise a better strategy to eliminate the unnecessary intermediate `Box`.
struct OpenBlockFile(Arc<dyn BlockDevice>);

impl FileOps for OpenBlockFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = writer.avail();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.0.metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return Ok(0);
        }

        let read_len = total.min(device_size - offset);
        {
            // `VmIo::read` does not allow short writes,
            // so the writer must be precisely limited here.
            let mut limited_writer = writer.clone_exclusive();
            limited_writer.limit(read_len);
            self.0.read(offset, &mut limited_writer)?;
        }
        writer.skip(read_len);
        Ok(read_len)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = reader.remain();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.0.metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return_errno_with_message!(
                Errno::ENOSPC,
                "the write offset is beyond the block device"
            );
        }

        let write_len = total.min(device_size - offset);
        {
            // `VmIo::write` does not allow short writes,
            // so the reader must be precisely limited here.
            let mut limited_reader = reader.clone();
            limited_reader.limit(write_len);
            self.0.write(offset, &mut limited_reader)?;
        }
        reader.skip(write_len);
        Ok(write_len)
    }
}

impl Pollable for OpenBlockFile {
    fn poll(&self, mask: IoEvents, _: Option<&mut PollHandle>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

impl PerOpenFileOps for OpenBlockFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }

    fn seek_end(&self) -> Result<Option<usize>> {
        Ok(Some(self.0.metadata().nr_sectors * SECTOR_SIZE))
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ BlkGetSectorSize => {
                // TODO: Query the per-device logical block size once block device metadata
                // exposes it. For now, report the effective minimum I/O granularity enforced
                // by Asterinas filesystems so userspace can use `BLKSSZGET` for `O_DIRECT`
                // alignment.
                let sector_size = SECTOR_SIZE.max(BLOCK_SIZE) as i32;
                current_userspace!().write_val(raw_ioctl.arg(), &sector_size)?;
                Ok(0)
            }
            cmd @ BlkGetSize64 => {
                let size = (self.0.metadata().nr_sectors * SECTOR_SIZE) as u64;
                cmd.write(&size)?;
                Ok(0)
            }
            _ => return_errno_with_message!(
                Errno::ENOTTY,
                "the ioctl command is not supported by block devices"
            ),
        })
    }

    fn settable_status_flags(&self) -> SettableStatusFlags {
        SettableStatusFlags::minimal().with_o_direct()
    }

    fn sync(&self, _mode: SyncMode) -> Result<()> {
        match self.0.sync()? {
            // Linux treats an unsupported block-device flush as success.
            // Reference: <https://github.com/torvalds/linux/blob/v6.16/block/fops.c#L609-L611>
            BioStatus::Complete | BioStatus::NotSupported => Ok(()),
            status @ (BioStatus::NoSpace | BioStatus::IoError) => Err(status.into()),
            BioStatus::Init | BioStatus::Submit | BioStatus::Zeros => {
                return_errno_with_message!(Errno::EIO, "invalid block device flush status")
            }
        }
    }
}

pub(super) fn lookup(id: DeviceId) -> Option<Arc<dyn Device>> {
    let block_device = aster_block::lookup(id)?;

    let mut registry = DEVICE_REGISTRY.lock();
    let block_device_file = registry
        .entry(id.to_raw())
        .or_insert_with(move || Arc::new(BlockFile::new(block_device)))
        .clone();
    Some(block_device_file)
}

// TODO: Merge the two mapping tables, one is here and the other is in the block component.
// Maintaining two mapping tables is undesirable due to duplication and (potential) inconsistency.
static DEVICE_REGISTRY: Mutex<BTreeMap<u32, Arc<dyn Device>>> = Mutex::new(BTreeMap::new());
