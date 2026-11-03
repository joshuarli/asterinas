// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use aster_bigtcp::{
    errors::udp::{RecvError, SendError},
    socket::{UdpError, UdpErrorOrigin, UdpNextHop},
    wire::{IpAddress, IpEndpoint},
};

use crate::{
    events::IoEvents,
    net::{
        iface::{BoundUdpPort, Iface, UdpSocket},
        route::lookup_iface,
        socket::{ip::common::get_ephemeral_endpoint_on, util::{RecvFlags, RecvOutput, SendFlags, datagram_common}},
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

/// What the network stack knows about a received datagram besides its payload.
pub(super) struct ReceivedMeta {
    pub(super) remote: IpEndpoint,
    pub(super) local_address: Option<IpAddress>,
    pub(super) arrived_at: Duration,
    pub(super) ttl: u8,
    pub(super) tos: u8,
    pub(super) ifindex: u32,
}

pub(super) struct BoundDatagram {
    bound_socket: UdpSocket,
    remote_endpoint: Option<IpEndpoint>,
    connected_source: Option<IpAddress>,
}

impl BoundDatagram {
    pub(super) fn new(bound_socket: UdpSocket) -> Self {
        Self {
            bound_socket,
            remote_endpoint: None,
            connected_source: None,
        }
    }

    pub(super) fn bound_port(&self) -> &BoundUdpPort {
        self.bound_socket.bound_port()
    }

    pub(super) fn set_connected_source(&mut self, source: IpAddress) {
        self.bound_socket.set_receive_address(source);
        self.connected_source = Some(source);
    }

    pub(super) fn set_receive_errors(&self, enabled: bool) {
        self.bound_socket.set_receive_errors(enabled);
    }

    pub(super) fn set_hop_limit(&self, limit: u8) {
        self.bound_socket.set_hop_limit(limit);
    }

    pub(super) fn take_pending_error(&self) -> Option<UdpErrorOrigin> {
        self.bound_socket.take_pending_error()
    }

    pub(super) fn pop_network_error(&self) -> Option<UdpError> {
        self.bound_socket.pop_network_error()
    }

    /// Receives a datagram together with its arrival time and destination address.
    pub(super) fn try_recv_with_meta(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, ReceivedMeta)> {
        let result = self.bound_socket.recv(
            flags.receive_behavior(),
            |packet, udp_metadata, arrived_at_ns, ttl, tos, ifindex| {
                let message_len = packet.len();
                let copied_res = writer
                    .write(&mut VmReader::from(packet))
                    .map_err(Into::into);
                let meta = ReceivedMeta {
                    remote: udp_metadata.endpoint,
                    local_address: udp_metadata.local_address,
                    arrived_at: Duration::from_nanos(arrived_at_ns),
                    ttl,
                    tos,
                    ifindex,
                };
                (copied_res, meta, message_len)
            },
        );

        match result {
            Ok((Ok(copied_len), meta, message_len)) => {
                let output = RecvOutput::new_for_packet(flags, copied_len, message_len);
                Ok((output, meta))
            }
            Ok((Err(e), _, _)) => Err(e),
            Err(RecvError::Exhausted) => {
                return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty")
            }
            Err(RecvError::Truncated) => {
                unreachable!("`recv` should never fail with `RecvError::Truncated`")
            }
        }
    }

    /// Sends a datagram. A nonzero `tx_tag` asks for a transmit timestamp.
    pub(super) fn try_send_tagged(
        &self,
        reader: &mut dyn MultiRead,
        remote: &IpEndpoint,
        iface: &Arc<Iface>,
        source: IpAddress,
        tx_tag: u32,
        tos: u8,
        next_hop: UdpNextHop,
    ) -> Result<usize> {
        let mut meta = aster_bigtcp::socket::UdpMetadata::from(*remote);
        meta.meta.id = tx_tag;
        let result = self
            .bound_socket
            .send(reader.sum_lens(), meta, iface.index(), source, tos, next_hop, |socket_buffer| {
                reader
                    .read(&mut VmWriter::from(socket_buffer))
                    .map_err(Into::into)
            });

        match result {
            Ok(inner) => inner,
            Err(SendError::TooLarge) => {
                return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
            }
            Err(SendError::Unaddressable) => {
                return_errno_with_message!(Errno::EINVAL, "the destination address is invalid");
            }
            Err(SendError::BufferFull) => {
                return_errno_with_message!(Errno::EAGAIN, "the send buffer is full");
            }
        }
    }

    /// Takes the oldest pending transmit timestamp.
    pub(super) fn pop_tx_timestamp(&self) -> Option<aster_bigtcp::socket::TxTimestamp> {
        self.bound_socket.pop_tx_timestamp()
    }
}

impl datagram_common::Bound for BoundDatagram {
    type Endpoint = IpEndpoint;

    fn local_endpoint(&self) -> Self::Endpoint {
        let mut endpoint = self.bound_socket.local_endpoint();
        if let Some(source) = self.connected_source { endpoint.addr = source; }
        endpoint
    }

    fn remote_endpoint(&self) -> Option<&Self::Endpoint> {
        self.remote_endpoint.as_ref()
    }

    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) {
        self.remote_endpoint = Some(*endpoint);
        self.bound_socket.set_error_peer(Some(*endpoint));
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, Self::Endpoint)> {
        let (output, meta) = self.try_recv_with_meta(writer, flags)?;
        Ok((output, meta.remote))
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &Self::Endpoint,
        _flags: SendFlags,
    ) -> Result<usize> {
        let iface = lookup_iface(remote.addr)?;
        let local = self.local_endpoint();
        let source = if local.addr.is_unspecified() { get_ephemeral_endpoint_on(&iface, remote)?.addr } else { local.addr };
        self.try_send_tagged(reader, remote, &iface, source, 0, 0, UdpNextHop::Routed)
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        if self.bound_socket.can_recv() {
            events |= IoEvents::IN;
        }
        if self.bound_socket.can_send() {
            events |= IoEvents::OUT;
        }
        events | if self.bound_socket.has_tx_timestamp() || self.bound_socket.has_network_error() {
            IoEvents::ERR
        } else {
            IoEvents::empty()
        }
    }
}
