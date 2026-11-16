// SPDX-License-Identifier: MPL-2.0

//! TCP transport identities and diagnostic snapshots.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::IpEndpoint;

pub use smoltcp::socket::tcp::{State as TcpState, TcpTelemetry};

/// The address family selected when the socket file was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpAddressFamily {
    Ipv4,
    Ipv6,
}

static TCP_TABLE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Returns the generation of the TCP transport inventory.
pub fn tcp_table_generation() -> u64 { TCP_TABLE_GENERATION.load(Ordering::Acquire) }

pub(crate) fn tcp_table_changed() { TCP_TABLE_GENERATION.fetch_add(1, Ordering::Release); }

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(1);

static LIVE_TCP_IDENTITIES: AtomicUsize = AtomicUsize::new(0);

/// Returns the number of TCP socket identities that are still referenced.
///
/// An identity lives as long as its socket file or its transport, whichever is longer.
pub fn tcp_identity_count() -> usize { LIVE_TCP_IDENTITIES.load(Ordering::Relaxed) }

pub(crate) fn next_cookie() -> u64 { NEXT_COOKIE.fetch_add(1, Ordering::Relaxed) }

/// Identity retained by a TCP transport after its file is closed.
pub struct TcpDiagnosticIdentity {
    cookie: u64,
    family: TcpAddressFamily,
    cgroup: u64,
    file: SpinLock<TcpDiagnosticFile, BottomHalfDisabled>,
}

struct TcpDiagnosticFile {
    owner: Option<Arc<AtomicU32>>,
    inherited_uid: u32,
    inode: u64,
}

impl TcpDiagnosticIdentity {
    /// Creates an identity for a TCP file or an unaccepted connection.
    pub fn new(owner: Arc<AtomicU32>, inode: u64, family: TcpAddressFamily, cgroup: u64) -> Arc<Self> {
        LIVE_TCP_IDENTITIES.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            cookie: next_cookie(),
            family,
            cgroup,
            file: SpinLock::new(TcpDiagnosticFile { owner: Some(owner), inherited_uid: 0, inode }),
        })
    }

    /// Creates a distinct identity for an unaccepted child.
    pub(crate) fn child(&self) -> Arc<Self> {
        let file = self.file.lock();
        let uid = file.owner.as_ref().map_or(file.inherited_uid, |owner| owner.load(Ordering::Relaxed));
        LIVE_TCP_IDENTITIES.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            cookie: next_cookie(),
            family: self.family,
            cgroup: self.cgroup,
            file: SpinLock::new(TcpDiagnosticFile { owner: None, inherited_uid: uid, inode: 0 }),
        })
    }

    /// Associates the accepted file with its existing transport identity.
    pub fn attach(&self, owner: Arc<AtomicU32>, inode: u64) {
        *self.file.lock() = TcpDiagnosticFile { owner: Some(owner), inherited_uid: 0, inode };
    }

    /// Clears the inode when the last reference to the file is released.
    pub fn detach(&self) {
        self.file.lock().inode = 0;
    }

    /// Returns whether the socket file was closed while the transport lives on.
    pub(crate) fn orphaned(&self) -> bool {
        let file = self.file.lock();
        file.owner.is_some() && file.inode == 0
    }

    pub(crate) fn family(&self) -> TcpAddressFamily { self.family }

    pub(crate) fn cgroup(&self) -> u64 { self.cgroup }

    pub(crate) fn values(&self) -> (u64, u64, u32) {
        let file = self.file.lock();
        (self.cookie, file.inode, file.owner.as_ref().map_or(file.inherited_uid, |owner| owner.load(Ordering::Relaxed)))
    }
}

impl Drop for TcpDiagnosticIdentity {
    fn drop(&mut self) {
        LIVE_TCP_IDENTITIES.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts of the TCP transports of one interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpCounts {
    /// Hashed transports of IPv4 sockets, excluding time-wait and half-open ones.
    pub in_use_ipv4: usize,
    /// Hashed transports of IPv6 sockets, excluding time-wait and half-open ones.
    pub in_use_ipv6: usize,
    pub time_wait: usize,
    /// Transports whose socket file was closed, excluding time-wait ones.
    pub orphaned: usize,
    /// Time-wait transports whose socket file was closed.
    pub orphaned_time_wait: usize,
}

/// A point-in-time view of one TCP transport.
#[derive(Clone, Debug)]
pub struct TcpSocketSnapshot {
    pub telemetry: TcpTelemetry,
    pub cgroup: u64,
    pub family: TcpAddressFamily,
    pub local: IpEndpoint,
    pub remote: IpEndpoint,
    pub state: TcpState,
    pub read_queue: u32,
    pub write_queue: u32,
    pub cookie: u64,
    pub inode: u64,
    pub uid: u32,
    pub shutdown: u8,
    pub orphan: bool,
}

/// A point-in-time view of one UDP socket.
#[derive(Clone, Debug)]
pub struct UdpSocketSnapshot {
    pub local: IpEndpoint,
    pub remote: Option<IpEndpoint>,
    pub device: Option<u32>,
    pub read_queue: u32,
    pub write_queue: u32,
    pub cookie: u64,
    pub inode: u64,
    pub uid: u32,
}
