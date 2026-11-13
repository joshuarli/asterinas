// SPDX-License-Identifier: MPL-2.0

//! TCP transport identities and diagnostic snapshots.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::IpEndpoint;

pub use smoltcp::socket::tcp::State as TcpState;

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

/// Identity retained by a TCP transport after its file is closed.
pub struct TcpDiagnosticIdentity {
    cookie: u64,
    family: TcpAddressFamily,
    file: SpinLock<TcpDiagnosticFile, BottomHalfDisabled>,
}

struct TcpDiagnosticFile {
    owner: Option<Arc<AtomicU32>>,
    inherited_uid: u32,
    inode: u64,
}

impl TcpDiagnosticIdentity {
    /// Creates an identity for a TCP file or an unaccepted connection.
    pub fn new(owner: Arc<AtomicU32>, inode: u64, family: TcpAddressFamily) -> Arc<Self> {
        Arc::new(Self {
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            family,
            file: SpinLock::new(TcpDiagnosticFile { owner: Some(owner), inherited_uid: 0, inode }),
        })
    }

    /// Creates a distinct identity for an unaccepted child.
    pub(crate) fn child(&self) -> Arc<Self> {
        let file = self.file.lock();
        let uid = file.owner.as_ref().map_or(file.inherited_uid, |owner| owner.load(Ordering::Relaxed));
        Arc::new(Self {
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            family: self.family,
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

    pub(crate) fn family(&self) -> TcpAddressFamily { self.family }

    pub(crate) fn values(&self) -> (u64, u64, u32) {
        let file = self.file.lock();
        (self.cookie, file.inode, file.owner.as_ref().map_or(file.inherited_uid, |owner| owner.load(Ordering::Relaxed)))
    }
}

/// A point-in-time view of one TCP transport.
#[derive(Clone, Debug)]
pub struct TcpSocketSnapshot {
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
}
