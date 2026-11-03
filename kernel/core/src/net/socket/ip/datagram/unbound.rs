// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::AtomicU32;
use aster_bigtcp::{iface::BindPortConfig, socket::UdpSocket, wire::{IpAddress, IpEndpoint, Ipv4Address}};

use super::{bound::BoundDatagram, observer::DatagramObserver};
use crate::{
    events::IoEvents,
    net::{
        iface::udp_registry,
        route::lookup_local_iface,
        socket::{
            util::{BoundDevice, check_port_privilege, datagram_common},
        },
    },
    prelude::*,
    process::signal::Pollee,
};

pub(super) struct UnboundDatagram {
    owner: Arc<AtomicU32>,
}

impl UnboundDatagram {
    pub(super) fn new(owner: Arc<AtomicU32>) -> Self {
        Self { owner }
    }
}

pub(super) struct BindOptions {
    pub(super) can_reuse: bool,
    pub(super) reuse_port: bool,
    pub(super) device: BoundDevice,
}

impl datagram_common::Unbound for UnboundDatagram {
    type Endpoint = IpEndpoint;
    type BindOptions = BindOptions;

    type Bound = BoundDatagram;

    fn bind(
        &mut self,
        endpoint: &Self::Endpoint,
        pollee: &Pollee,
        options: BindOptions,
    ) -> Result<Self::Bound> {
        check_port_privilege(endpoint.port)?;
        let device = options.device.iface()?;
        if !endpoint.addr.is_unspecified() {
            let owner = lookup_local_iface(endpoint.addr)?;
            if device.is_some_and(|device| !Arc::ptr_eq(device, &owner)) {
                return_errno_with_message!(Errno::EADDRNOTAVAIL, "the address does not belong to the selected interface");
            }
        }
        let config = BindPortConfig::new(*endpoint, options.can_reuse);
        let reservation = udp_registry().bind(config, device.map(|iface| iface.index()), options.reuse_port, self.owner.clone())?;
        let bound_socket = UdpSocket::new_bind(reservation, DatagramObserver::new(pollee.clone()));

        Ok(BoundDatagram::new(bound_socket))
    }

    fn bind_ephemeral(
        &mut self,
        _remote_endpoint: &Self::Endpoint,
        pollee: &Pollee,
    ) -> Result<Self::Bound> {
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0);
        self.bind(
            &endpoint,
            pollee,
            BindOptions {
                can_reuse: false,
                reuse_port: false,
                device: BoundDevice::NONE,
            },
        )
    }

    fn check_io_events(&self) -> IoEvents {
        IoEvents::OUT
    }
}
