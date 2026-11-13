// SPDX-License-Identifier: MPL-2.0

use super::{controller, message::SockDiagMessage};
use crate::{
    events::IoEvents,
    net::socket::{
        netlink::{NetlinkSocketAddr, common::BoundNetlink, message::CMsgSegHdr},
        util::{RecvFlags, RecvOutput, SendFlags, datagram_common},
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

impl datagram_common::Bound for BoundNetlink<SockDiagMessage> {
    type Endpoint = NetlinkSocketAddr;

    fn local_endpoint(&self) -> Self::Endpoint { self.handle.addr() }
    fn bind(&mut self, endpoint: &Self::Endpoint) -> Result<()> { self.bind_common(endpoint) }
    fn remote_endpoint(&self) -> Option<&Self::Endpoint> { Some(&self.remote_addr) }
    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) { self.remote_addr = *endpoint; }

    fn try_send(&self, reader: &mut dyn MultiRead, remote: &Self::Endpoint, _flags: SendFlags) -> Result<usize> {
        if *remote != NetlinkSocketAddr::new_unspecified() {
            return_errno_with_message!(Errno::ECONNREFUSED, "socket diagnostic netlink destination is not the kernel");
        }
        let total = reader.sum_lens();
        while reader.sum_lens() >= size_of::<CMsgSegHdr>() {
            let Some(header) = reader.read_val_opt::<CMsgSegHdr>()? else { break };
            let Some(payload_len) = (header.len as usize).checked_sub(size_of::<CMsgSegHdr>()) else { break };
            if payload_len > reader.sum_lens() { break; }
            let padding = ((4 - payload_len % 4) % 4).min(reader.sum_lens() - payload_len);
            let mut payload = Vec::new();
            payload.try_reserve_exact(payload_len).map_err(|_| {
                Error::with_message(Errno::ENOMEM, "cannot allocate the socket diagnostic netlink request")
            })?;
            payload.resize(payload_len, 0);
            reader.read(&mut VmWriter::from(payload.as_mut_slice()))?;
            reader.skip_some(padding);
            controller::handle(&header, &payload, self.handle.port())?;
        }
        Ok(total)
    }

    fn try_recv(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, Self::Endpoint)> {
        let mut queue = self.receive_queue.lock();
        queue.dequeue_if(|response, len| {
            let copied = len.min(writer.sum_lens());
            response.write_to(writer)?;
            Ok((flags.receive_behavior().will_consume_data() && response.advance(),
                (RecvOutput::new_for_packet(flags, copied, len), NetlinkSocketAddr::new_unspecified())))
        })
    }

    fn check_io_events(&self) -> IoEvents { self.check_io_events_common() }
}
