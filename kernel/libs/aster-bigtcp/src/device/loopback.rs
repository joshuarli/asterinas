// SPDX-License-Identifier: MPL-2.0

use alloc::collections::VecDeque;
use core::fmt::{Debug, Formatter};

use super::{
    AnyNetworkDevice, ChecksumCapabilities, DeviceCapabilities, EthernetAddress, Medium, NetError,
};
use crate::packet::{FreshTxPacket, LinkLayer, RxPacket, TxPacket};

/// A loopback network device.
pub struct Loopback {
    received: VecDeque<RxPacket<LinkLayer>>,
}

impl Debug for Loopback {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Loopback").field("queued", &self.received.len()).finish()
    }
}

impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every transmitted packet is made available for reception in FIFO order.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { received: VecDeque::new() }
    }
}

impl AnyNetworkDevice for Loopback {
    fn mac_addr(&self) -> EthernetAddress {
        EthernetAddress::default()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 65535;
        capabilities.medium = Medium::Ip;
        capabilities.checksum = ChecksumCapabilities::ignored();
        capabilities
    }

    fn mtu(&self) -> usize {
        // Reference: <https://elixir.bootlin.com/linux/v7.1/source/drivers/net/loopback.c>.
        65536
    }

    fn can_receive(&self) -> bool {
        !self.received.is_empty()
    }

    fn can_send(&self) -> bool {
        self.received.len() < 256
    }

    fn receive(&mut self) -> Result<RxPacket<LinkLayer>, NetError> {
        self.received.pop_front().ok_or(NetError::NotReady)
    }

    fn send(&mut self, packet: TxPacket<LinkLayer>) -> Result<(), NetError> {
        if !self.can_send() { return Err(NetError::Busy); }
        self.received.push_back(packet.to_rx_packet().ok_or(NetError::NoMemory)?);
        Ok(())
    }

    fn alloc_tx_buffer(payload_len: usize) -> Result<FreshTxPacket, ostd::Error> {
        FreshTxPacket::alloc(payload_len)
    }

    fn free_processed_tx_buffers(&mut self) {}

    fn notify_poll_end(&mut self) {}
}
