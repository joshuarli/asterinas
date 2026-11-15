// SPDX-License-Identifier: MPL-2.0

use core::ops::Bound::{Excluded, Unbounded};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;

use super::{Socket, unix::UnixSocketAddr};
use crate::prelude::*;

static SOCKETS: SpinLock<BTreeMap<u64, Weak<dyn Socket>>, BottomHalfDisabled> = SpinLock::new(BTreeMap::new());

pub(crate) enum ProcSocket {
    Unix { inode: u64, kind: u32, state: u8, listening: bool, addr: UnixSocketAddr },
    Netlink { inode: u64, protocol: u32, port: u32, groups: u32, kind: u8, connected: bool, dst_port: u32, dst_group: u32, recv_used: u32, recv_buf: u32, send_buf: u32 },
}

pub(super) fn register<T: Socket + 'static>(socket: &Arc<T>) {
    let inode = socket.common().path().inode().ino();
    let socket: Arc<dyn Socket> = socket.clone();
    SOCKETS.lock().insert(inode, Arc::downgrade(&socket));
}

pub(super) fn unregister(inode: u64) {
    SOCKETS.lock().remove(&inode);
}

pub(crate) fn page(cursor: Option<u64>, limit: usize) -> (Option<u64>, Vec<ProcSocket>) {
    let (next, sockets): (Option<u64>, Vec<_>) = {
        let sockets = SOCKETS.lock();
        let mut next = None;
        let mut page = Vec::new();
        for (&inode, socket) in sockets.range((cursor.map_or(Unbounded, Excluded), Unbounded)).take(limit) {
            next = Some(inode);
            if let Some(socket) = socket.upgrade() { page.push(socket); }
        }
        (next, page)
    };
    (next, sockets.into_iter().filter_map(|socket| socket.proc_info()).collect())
}
