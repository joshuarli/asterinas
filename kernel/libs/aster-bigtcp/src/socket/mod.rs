// SPDX-License-Identifier: MPL-2.0

mod bound;
mod event;
mod option;
mod unbound;

pub use bound::{
    ConnectState, NeedIfacePoll, RawTcpSocketExt, ReceiveBehavior, TcpConnection, TcpListener,
    TxTimestamp, UdpError, UdpErrorOrigin, UdpFragmentation, UdpIpv4Options, IpNextHop, UdpSocket,
};
pub(crate) use bound::{TcpConnectionBg, TcpListenerBg, TcpProcessResult, UdpSocketBg};
pub use event::{SocketEventObserver, SocketEvents};
pub use smoltcp::socket::udp::UdpMetadata;
pub use option::{RawTcpOption, RawTcpSetOption};
pub use unbound::{
    TCP_RECV_BUF_LEN, TCP_SEND_BUF_LEN, UDP_RECV_PAYLOAD_LEN, UDP_SEND_PAYLOAD_LEN,
};
