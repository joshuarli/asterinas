// SPDX-License-Identifier: MPL-2.0

//! Controlling the balancing between CPU-local free pools and the global free pool.

use ostd::{cpu::num_cpus, mm::PAGE_SIZE};

use super::{BuddyOrder, BuddySet, MAX_LOCAL_BUDDY_ORDER, OnDemandGlobalLock, lesser_order_of};

use crate::chunk::{size_of_order, split_to_order};

/// Controls the expected size of cache for each CPU-local free pool.
///
/// The expected size will be the size of `GLOBAL_POOL` divided by the number
/// of the CPUs, and then divided by this constant.
const CACHE_EXPECTED_PORTION: usize = 2;

/// Returns the expected size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_expected_size(global_size: usize) -> usize {
    global_size / num_cpus() / CACHE_EXPECTED_PORTION
}

/// Controls the minimal size of cache for each CPU-local free pool.
///
/// The minimal will be the expected size divided by this constant.
const CACHE_MINIMAL_PORTION: usize = 8;

/// Returns the minimal size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_minimal_size(global_size: usize) -> usize {
    cache_expected_size(global_size) / CACHE_MINIMAL_PORTION
}

/// Controls the maximal size of cache for each CPU-local free pool.
///
/// The maximal will be the expected size multiplied by this constant.
const CACHE_MAXIMAL_MULTIPLIER: usize = 2;

/// Returns the maximal size of cache for each CPU-local free pool.
///
/// It depends on the size of the global free pool.
fn cache_maximal_size(global_size: usize) -> usize {
    cache_expected_size(global_size) * CACHE_MAXIMAL_MULTIPLIER
}

/// What balancing a local cache against the global free pool has to move.
#[derive(Debug, PartialEq, Eq)]
enum Rebalance {
    Keep,
    ToGlobal(BuddyOrder),
    ToLocal(BuddyOrder),
}

/// Decides what to move for the given sizes of the global pool and a local cache.
///
/// Nothing is moved when the amount to move is smaller than a page, which
/// happens when the global pool is almost exhausted.
fn plan(global_size: usize, local_size: usize) -> Rebalance {
    let minimal_local_size = cache_minimal_size(global_size);
    let expected_local_size = cache_expected_size(global_size);
    let maximal_local_size = cache_maximal_size(global_size);

    if local_size >= maximal_local_size {
        let expected_removal = local_size - expected_local_size;
        if expected_removal < PAGE_SIZE {
            return Rebalance::Keep;
        }
        Rebalance::ToGlobal(lesser_order_of(expected_removal))
    } else if local_size < minimal_local_size {
        let expected_allocation = expected_local_size - local_size;
        if expected_allocation < PAGE_SIZE {
            return Rebalance::Keep;
        }
        Rebalance::ToLocal(lesser_order_of(expected_allocation))
    } else {
        Rebalance::Keep
    }
}

/// Balances a local cache and the global free pool.
pub(super) fn balance(
    local: &mut BuddySet<MAX_LOCAL_BUDDY_ORDER>,
    global: &mut OnDemandGlobalLock,
) {
    match plan(global.get_global_size(), local.total_size()) {
        Rebalance::Keep => {}
        Rebalance::ToGlobal(order) => balance_to(local, &mut *global.get(), order),
        Rebalance::ToLocal(order) => balance_to(&mut *global.get(), local, order),
    }
}

const MAX_CHUNKS_PER_BALANCE: usize = 64;

/// Balances from `a` to `b`.
fn balance_to<const MAX_ORDER1: BuddyOrder, const MAX_ORDER2: BuddyOrder>(
    a: &mut BuddySet<MAX_ORDER1>,
    b: &mut BuddySet<MAX_ORDER2>,
    order: BuddyOrder,
) {
    let mut remaining = size_of_order(order);
    let mut chunk_order = order;

    for _ in 0..MAX_CHUNKS_PER_BALANCE {
        while chunk_order > 0 && size_of_order(chunk_order) > remaining {
            chunk_order -= 1;
        }
        let addr = loop {
            if let Some(addr) = a.alloc_chunk(chunk_order) {
                break addr;
            }
            if chunk_order == 0 {
                return;
            }
            chunk_order -= 1;
        };

        if chunk_order >= MAX_ORDER2 {
            let inserted_order = MAX_ORDER2 - 1;
            split_to_order(addr, chunk_order, inserted_order).for_each(|addr| {
                b.insert_chunk(addr, inserted_order);
            });
        } else {
            b.insert_chunk(addr, chunk_order);
        }

        remaining -= size_of_order(chunk_order);
        if remaining == 0 {
            return;
        }
    }
}

#[cfg(ktest)]
mod test {
    use ostd::{mm::PAGE_SIZE, prelude::ktest};

    use super::*;
    use crate::test::MockMemoryRegion;

    #[ktest]
    fn plan_moves_nothing_when_the_global_pool_is_almost_exhausted() {
        assert_eq!(plan(0, 0), Rebalance::Keep);
        assert_eq!(plan(PAGE_SIZE, 0), Rebalance::Keep);

        let cpus = num_cpus();
        for global_pages in 0..(4 * cpus * CACHE_EXPECTED_PORTION) {
            let global_size = global_pages * PAGE_SIZE;
            let expected = cache_expected_size(global_size);
            for local_pages in 0..(4 * cpus * CACHE_EXPECTED_PORTION) {
                let local_size = local_pages * PAGE_SIZE;
                match plan(global_size, local_size) {
                    Rebalance::Keep => {}
                    Rebalance::ToLocal(order) => {
                        assert!(size_of_order(order) <= expected - local_size);
                        assert!(expected - local_size >= PAGE_SIZE);
                    }
                    Rebalance::ToGlobal(order) => {
                        assert!(size_of_order(order) <= local_size - expected);
                        assert!(local_size - expected >= PAGE_SIZE);
                    }
                }
            }
        }
    }

    #[ktest]
    fn plan_returns_surplus_and_refills_a_starved_cache() {
        let cpus = num_cpus();
        let global_size = 1024 * cpus * CACHE_EXPECTED_PORTION * PAGE_SIZE;
        let expected = cache_expected_size(global_size);
        assert_eq!(plan(global_size, expected), Rebalance::Keep);
        assert_eq!(
            plan(global_size, 3 * expected),
            Rebalance::ToGlobal(lesser_order_of(2 * expected))
        );
        assert_eq!(
            plan(global_size, 0),
            Rebalance::ToLocal(lesser_order_of(expected))
        );
    }

    #[ktest]
    fn balance_to_terminates_when_only_small_chunks_remain() {
        let region_order = 8;
        let region = MockMemoryRegion::alloc(size_of_order(region_order));
        let mut from = BuddySet::<20>::new_empty();
        let mut to = BuddySet::<20>::new_empty();
        let isolated_chunks = size_of_order(region_order) / PAGE_SIZE / 2;
        for index in 0..isolated_chunks {
            from.insert_chunk(region.paddr() + index * 2 * PAGE_SIZE, 0);
        }
        assert_eq!(from.total_size(), isolated_chunks * PAGE_SIZE);

        balance_to(&mut from, &mut to, 17);

        assert_eq!(to.total_size(), MAX_CHUNKS_PER_BALANCE * PAGE_SIZE);
        assert_eq!(
            from.total_size() + to.total_size(),
            isolated_chunks * PAGE_SIZE
        );

        from.drain_chunks(|_, _| {});
        to.drain_chunks(|_, _| {});
    }

    #[ktest]
    fn balance_to_moves_no_more_than_the_requested_order() {
        let region_order = 6;
        let region = MockMemoryRegion::alloc(size_of_order(region_order));
        let mut from = BuddySet::<20>::new_empty();
        let mut to = BuddySet::<20>::new_empty();
        from.insert_chunk(region.paddr(), region_order);

        balance_to(&mut from, &mut to, 3);

        assert_eq!(to.total_size(), size_of_order(3));
        assert_eq!(from.total_size(), size_of_order(region_order) - size_of_order(3));

        from.drain_chunks(|_, _| {});
        to.drain_chunks(|_, _| {});
    }
}
