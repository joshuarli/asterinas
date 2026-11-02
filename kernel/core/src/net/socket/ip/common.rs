// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::BindError,
    iface::BindPortConfig,
    wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address},
};

use crate::{
    net::{
        iface::{Iface, config},
        route,
        socket::util::check_port_privilege,
    },
    prelude::*,
};

pub(super) fn resolve_bind_iface_and_config(
    endpoint: &IpEndpoint,
    can_reuse: bool,
) -> Result<(Arc<Iface>, BindPortConfig)> {
    check_port_privilege(endpoint.port)?;

    let iface = route::lookup_local_iface(endpoint.addr)?;

    let bind_port_config = BindPortConfig::new(*endpoint, can_reuse);

    Ok((iface, bind_port_config))
}

impl From<BindError> for Error {
    fn from(value: BindError) -> Self {
        match value {
            BindError::Exhausted => {
                Error::with_message(Errno::EAGAIN, "no ephemeral port is available")
            }
            BindError::InUse => {
                Error::with_message(Errno::EADDRINUSE, "the address is already in use")
            }
        }
    }
}

/// Resolves the interface and port configuration of a socket restricted to `iface`.
///
/// Such a socket receives only what arrives on `iface`, so it may bind the unspecified address.
/// A specified address must belong to `iface`.
pub(super) fn resolve_device_bind_iface_and_config(
    endpoint: &IpEndpoint,
    can_reuse: bool,
    iface: &Arc<Iface>,
) -> Result<(Arc<Iface>, BindPortConfig)> {
    check_port_privilege(endpoint.port)?;

    if !endpoint.addr.is_unspecified() {
        let owner = route::lookup_local_iface(endpoint.addr)?;
        if !Arc::ptr_eq(&owner, iface) {
            return_errno_with_message!(
                Errno::EADDRNOTAVAIL,
                "the address does not belong to the interface the socket is bound to"
            );
        }
    }

    Ok((iface.clone(), BindPortConfig::new(*endpoint, can_reuse)))
}

pub(super) fn get_ephemeral_endpoint(remote_endpoint: &IpEndpoint) -> Result<IpEndpoint> {
    let iface = route::lookup_iface(remote_endpoint.addr)?;
    get_ephemeral_endpoint_on(&iface, remote_endpoint)
}

/// Returns the endpoint with an ephemeral port that sends to `remote_endpoint` through `iface`.
pub(super) fn get_ephemeral_endpoint_on(
    iface: &Arc<Iface>,
    remote_endpoint: &IpEndpoint,
) -> Result<IpEndpoint> {
    let route_dst = remote_endpoint.addr;

    let source = match route_dst {
        IpAddress::Ipv4(_) => config::primary_ipv4_address(iface)
            .map(IpAddress::Ipv4)
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the route output iface has no IPv4 address",
                )
            })?,
        IpAddress::Ipv6(_) => iface
            .ipv6_cidr()
            .map(|cidr| IpAddress::Ipv6(cidr.address()))
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the route output iface has no IPv6 address",
                )
            })?,
    };

    Ok(IpEndpoint::new(source, 0))
}

/// Maps an unspecified `connect` destination to the loopback address.
///
/// Linux treats `connect` to an unspecified address as connecting to localhost.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/net/ipv4/route.c#L2803-L2812>.
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/net/ipv6/tcp_ipv6.c#L171-L181>.
pub(super) fn map_unspecified_to_localhost(mut endpoint: IpEndpoint) -> IpEndpoint {
    endpoint.addr = match endpoint.addr {
        IpAddress::Ipv4(address) if address.is_unspecified() => Ipv4Address::LOCALHOST.into(),
        IpAddress::Ipv6(address) if address.is_unspecified() => Ipv6Address::LOCALHOST.into(),
        address => address,
    };
    endpoint
}
