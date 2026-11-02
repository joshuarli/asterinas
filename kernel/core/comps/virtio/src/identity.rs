// SPDX-License-Identifier: MPL-2.0

//! Where a virtio device sits and how Linux numbers it.

/// Where the transport of a virtio device sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioPlacement {
    /// A memory-mapped transport at `base`, the `ordinal`-th one found.
    Mmio { ordinal: u32, base: usize },
    /// A function of a PCI device.
    Pci { bus: u8, device: u8, function: u8 },
}

/// A virtio device as the device model names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioIdentity {
    /// The number of the device among all virtio devices, in the order they were found:
    /// the `N` of `virtioN`.
    pub index: u32,
    /// Where the device's transport sits.
    pub placement: VirtioPlacement,
}
