// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::iface::InterfaceName;

use crate::{
    net::iface::{Iface, iter_all_ifaces},
    prelude::*,
};

/// The interface that `SO_BINDTODEVICE` restricts a socket to, if any.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BoundDevice(Option<u32>);

impl BoundDevice {
    pub(crate) const NONE: Self = Self(None);

    /// Selects the interface called `name`, or no interface for an empty name.
    pub(crate) fn from_name(name: &InterfaceName) -> Result<Self> {
        if name.is_empty() {
            return Ok(Self::NONE);
        }

        iter_all_ifaces()
            .find(|iface| iface.name() == name)
            .map(|iface| Self(Some(iface.index())))
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no interface has this name"))
    }

    pub(crate) fn is_bound(&self) -> bool {
        self.0.is_some()
    }

    /// The selected interface, or `None` when the socket is not restricted to one.
    pub(crate) fn iface(&self) -> Result<Option<&'static Arc<Iface>>> {
        let Some(index) = self.0 else {
            return Ok(None);
        };

        iter_all_ifaces()
            .find(|iface| iface.index() == index)
            .map(Some)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "the interface is gone"))
    }

    pub(crate) fn name(&self) -> Result<Option<InterfaceName>> {
        Ok(self.iface()?.map(|iface| *iface.name()))
    }
}
