// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::vec_deque::VecDeque, sync::Arc};

use ostd::{bus::BusProbeError, sync::SpinLock};

use super::{
    bus::{
        bus::{MmioDevice, MmioDriver},
        common_device::MmioCommonDevice,
    },
    device::VirtioMmioTransport,
};

#[derive(Debug)]
pub(crate) struct VirtioMmioDriver {
    devices: SpinLock<VecDeque<VirtioMmioTransport>>,
}

impl VirtioMmioDriver {
    pub(crate) fn pop_device_transport(&self) -> Option<VirtioMmioTransport> {
        self.devices.lock().pop_front()
    }

    pub(super) fn new() -> Self {
        VirtioMmioDriver {
            devices: SpinLock::new(VecDeque::new()),
        }
    }
}

impl MmioDriver for VirtioMmioDriver {
    fn probe(
        &self,
        device: MmioCommonDevice,
    ) -> Result<Arc<dyn MmioDevice>, (BusProbeError, MmioCommonDevice)> {
        let device = VirtioMmioTransport::new(device);
        let mmio_device = device.mmio_device().clone();
        self.devices.lock().push_back(device);
        Ok(mmio_device)
    }
}
