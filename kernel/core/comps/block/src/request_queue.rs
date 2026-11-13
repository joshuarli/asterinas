// SPDX-License-Identifier: MPL-2.0

use ostd::sync::{Mutex, WaitQueue};

use super::{
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio},
    id::Sid,
};
use crate::prelude::*;

/// A simple block I/O request queue backed by one internal FIFO queue.
///
/// It is a FIFO producer-consumer queue, where the producer (e.g., filesystem)
/// submits requests to the queue, and the consumer (e.g., block device driver)
/// continuously consumes and processes these requests from the queue.
///
/// It supports merging the new request with the front request if if the type
/// is same and the sector range is contiguous.
pub struct BioRequestSingleQueue {
    queue: Mutex<VecDeque<BioRequest>>,
    num_requests: AtomicUsize,
    wait_queue: WaitQueue,
    max_nr_segments_per_bio: usize,
    stats: Arc<crate::stats::IoStats>,
}

impl BioRequestSingleQueue {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self::with_max_nr_segments_per_bio(usize::MAX)
    }

    /// Creates an empty queue with the upper bound for the number of segments in a bio.
    pub fn with_max_nr_segments_per_bio(max_nr_segments_per_bio: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            num_requests: AtomicUsize::new(0),
            wait_queue: WaitQueue::new(),
            max_nr_segments_per_bio,
            stats: Arc::new(crate::stats::IoStats::new()),
        }
    }

    /// Returns a snapshot of this queue’s request accounting.
    pub fn io_stats(&self) -> crate::stats::IoStatsSnapshot {
        self.stats.snapshot()
    }

    /// Returns the upper limit for the number of segments per bio.
    pub fn max_nr_segments_per_bio(&self) -> usize {
        self.max_nr_segments_per_bio
    }

    /// Returns the number of requests currently in this queue.
    pub fn num_requests(&self) -> usize {
        self.num_requests.load(Ordering::Relaxed)
    }

    /// Enqueues a `SubmittedBio` to this queue.
    ///
    /// When enqueueing the `SubmittedBio`, try to insert it into the last request if the
    /// type is same and the sector range is contiguous.
    /// Otherwise, creates and inserts a new request for the `SubmittedBio`.
    ///
    /// This method will wake up the waiter if a new `BioRequest` is enqueued.
    pub fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        if bio.segments().len() > self.max_nr_segments_per_bio {
            return Err(BioEnqueueError::TooBig);
        }

        let mut queue = self.queue.lock();
        if let Some(request) = queue.front_mut()
            && request.can_merge(&bio)
            && request.num_segments() + bio.segments().len() <= self.max_nr_segments_per_bio
        {
            request.merge_bio(bio);
            return Ok(());
        }

        let new_request = BioRequest::new(bio, &self.stats);
        queue.push_front(new_request);
        self.inc_num_requests();
        drop(queue);

        self.wait_queue.wake_all();
        Ok(())
    }

    /// Dequeues a `BioRequest` from this queue.
    ///
    /// This method will wait until one request can be retrieved.
    pub fn dequeue(&self) -> BioRequest {
        let mut num_requests = self.num_requests();

        loop {
            if num_requests > 0 {
                let mut queue = self.queue.lock();
                if let Some(request) = queue.pop_back() {
                    self.dec_num_requests();
                    return request;
                }
            }

            num_requests = self.wait_queue.wait_until(|| {
                let num_requests = self.num_requests();
                if num_requests > 0 {
                    Some(num_requests)
                } else {
                    None
                }
            });
        }
    }

    fn dec_num_requests(&self) {
        self.num_requests.fetch_sub(1, Ordering::Relaxed);
    }

    fn inc_num_requests(&self) {
        self.num_requests.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for BioRequestSingleQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for BioRequestSingleQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("BioRequestSingleQueue")
            .field("num_requests", &self.num_requests())
            .field("queue", &self.queue.lock())
            .finish()
    }
}

/// A block I/O request dequeued from [`BioRequestSingleQueue`].
///
/// This `BioRequest` type is more friendly to storage medium than `SubmittedBio` for two reasons.
///
/// First, a `BioRequest` can represent a merged request over multiple `SubmittedBio`s
/// that (1) are of the same request type and (2) are contiguous in terms of target sectors.
/// This helps reduce the number of I/O requests submitted to the underlying storage medium.
///
/// Second, a `BioRequest` provides the physical sector addresses suitable for storage medium.
/// The sector addresses returned from `SubmittedBio::sid_range()` are logical ones:
/// they need to be adjusted with `SubmittedBio::sid_offset()` to calculate the physical ones.
/// This calculation is handled internally by `BioRequest`.
/// One can simply call `BioRequest::sid_range()` to obtain the physical sector addresses.
#[derive(Debug)]
pub struct BioRequest {
    /// The type of the I/O
    type_: BioType,
    /// The physical range of target sectors on the device
    sid_range: Range<Sid>,
    /// The number of segments
    num_segments: usize,
    /// The submitted bios
    bios: VecDeque<SubmittedBio>,
    records: Vec<crate::stats::IoRecord>,
}

impl BioRequest {
    /// Returns the type of the I/O.
    pub fn type_(&self) -> BioType {
        self.type_
    }

    /// Returns the range of the sector ID on the device.
    pub fn sid_range(&self) -> &Range<Sid> {
        &self.sid_range
    }

    /// Returns an iterator to the `SubmittedBio`s.
    pub fn bios(&self) -> impl Iterator<Item = &SubmittedBio> {
        self.bios.iter()
    }

    /// Completes request accounting and all its bios with the supplied status.
    pub fn complete(self, status: BioStatus) {
        assert!(status != BioStatus::Init && status != BioStatus::Submit);
        for record in self.records { record.complete(); }
        for bio in self.bios { bio.complete(status); }
    }

    /// Returns the number of sectors of this request.
    pub fn num_sectors(&self) -> usize {
        (self.sid_range.end.to_raw() - self.sid_range.start.to_raw())
            .try_into()
            .unwrap()
    }

    /// Returns the number of segments.
    pub fn num_segments(&self) -> usize {
        self.num_segments
    }

    /// Returns `true` if can merge the `SubmittedBio`, `false` otherwise.
    pub fn can_merge(&self, rq_bio: &SubmittedBio) -> bool {
        if rq_bio.type_() != self.type_ {
            return false;
        }

        let sid_offset = rq_bio.sid_offset();

        rq_bio.sid_range().start + sid_offset == self.sid_range.end
            || rq_bio.sid_range().end + sid_offset == self.sid_range.start
    }

    /// Merges the `SubmittedBio` into this request.
    ///
    /// The merged `SubmittedBio` can only be placed at the front or back.
    ///
    /// # Panics
    ///
    /// If the `SubmittedBio` can not be merged, this method will panic.
    pub fn merge_bio(&mut self, rq_bio: SubmittedBio) {
        assert!(self.can_merge(&rq_bio));

        let sectors = rq_bio.sid_range().end.to_raw() - rq_bio.sid_range().start.to_raw();
        if let Some(disk) = self.records.first_mut() { disk.merge(sectors); }
        if let Some(stats) = &rq_bio.partition_stats {
            if let Some(record) = self.records.iter_mut().skip(1).find(|record| record.belongs_to(stats)) {
                record.merge(sectors);
            } else if let Some(record) = stats.start(rq_bio.type_(), sectors) {
                self.records.push(record);
            }
        }
        let rq_bio_nr_segments = rq_bio.segments().len();
        let sid_offset = rq_bio.sid_offset();

        if rq_bio.sid_range().start + sid_offset == self.sid_range.end {
            self.sid_range.end = rq_bio.sid_range().end + sid_offset;
            self.bios.push_back(rq_bio);
        } else {
            self.sid_range.start = rq_bio.sid_range().start + sid_offset;
            self.bios.push_front(rq_bio);
        }

        self.num_segments += rq_bio_nr_segments;
    }
}

impl BioRequest {
    fn new(bio: SubmittedBio, stats: &Arc<crate::stats::IoStats>) -> Self {
        let sectors = bio.sid_range().end.to_raw() - bio.sid_range().start.to_raw();
        let mut records = Vec::new();
        if let Some(record) = stats.start(bio.type_(), sectors) { records.push(record); }
        if let Some(partition) = &bio.partition_stats
            && let Some(record) = partition.start(bio.type_(), sectors) { records.push(record); }
        let mut sid_range = bio.sid_range().clone();
        sid_range.start = sid_range.start + bio.sid_offset();
        sid_range.end = sid_range.end + bio.sid_offset();

        Self {
            type_: bio.type_(),
            records,
            sid_range,
            num_segments: bio.segments().len(),
            bios: {
                let mut bios = VecDeque::with_capacity(1);
                bios.push_front(bio);
                bios
            },
        }
    }
}

#[cfg(ktest)]
mod tests {
    use ::device_id::DeviceId;
    use io_util::batch::IoBatch;
    use ostd::prelude::ktest;

    use super::*;
    use crate::{
        BlockDevice, BlockDeviceMeta,
        bio::{Bio, BioDirection, BioSegment},
    };

    #[derive(Debug)]
    struct TestDevice(BioRequestSingleQueue);

    impl BlockDevice for TestDevice {
        fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
            self.0.enqueue(bio)
        }
        fn metadata(&self) -> BlockDeviceMeta { BlockDeviceMeta::default() }
        fn name(&self) -> &str { "test" }
        fn id(&self) -> DeviceId { DeviceId::null() }
    }

    #[ktest]
    fn merged_front_bios_complete_once_even_on_error() {
        let device = TestDevice(BioRequestSingleQueue::new());
        let mut batch = IoBatch::new();
        for sector in [8, 0] {
            let segment = BioSegment::alloc(1, BioDirection::ToDevice);
            Bio::new(BioType::Write, Sid::new(sector), vec![segment], None)
                .submit(&device, &mut batch).unwrap();
        }
        let active = device.0.io_stats();
        assert_eq!(active.in_flight, 1);
        assert_eq!(active.writes_merged, 1);
        device.0.dequeue().complete(BioStatus::IoError);
        let done = device.0.io_stats();
        assert_eq!(done.in_flight, 0);
        assert_eq!(done.writes, 1);
        assert_eq!(done.sectors_written, 16);
    }

    #[ktest]
    fn rejected_bio_does_not_start_a_request() {
        let device = TestDevice(BioRequestSingleQueue::with_max_nr_segments_per_bio(0));
        let mut batch = IoBatch::new();
        let before = crate::stats::submitted_sectors();
        let segment = BioSegment::alloc(1, BioDirection::ToDevice);
        let result = Bio::new(BioType::Write, Sid::new(0), vec![segment], None)
            .submit(&device, &mut batch);
        assert_eq!(result, Err(BioEnqueueError::TooBig));
        let stats = device.0.io_stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.writes, 0);
        assert_eq!(crate::stats::submitted_sectors().1 - before.1, 8);
    }

    #[ktest]
    fn submitted_reads_and_writes_use_kib_instead_of_sectors() {
        let device = TestDevice(BioRequestSingleQueue::new());
        let mut batch = IoBatch::new();
        let before = crate::stats::submitted_kib();
        for (type_, direction) in [(BioType::Read, BioDirection::FromDevice), (BioType::Write, BioDirection::ToDevice)] {
            let segment = BioSegment::alloc_inner(1, 0, 1024, direction);
            Bio::new(type_, Sid::new(0), vec![segment], None).submit(&device, &mut batch).unwrap();
        }
        let after = crate::stats::submitted_kib();
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
        device.0.dequeue().complete(BioStatus::Complete);
        device.0.dequeue().complete(BioStatus::Complete);
    }

    #[derive(Debug)]
    struct TestPartition {
        disk: Arc<TestDevice>,
        stats: Arc<crate::stats::IoStats>,
    }

    impl BlockDevice for TestPartition {
        fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
            bio.partition_stats = Some(self.stats.clone());
            self.disk.enqueue(bio)
        }
        fn metadata(&self) -> BlockDeviceMeta { BlockDeviceMeta::default() }
        fn name(&self) -> &str { "partition" }
        fn id(&self) -> DeviceId { DeviceId::null() }
    }

    #[ktest]
    fn one_merged_disk_request_keeps_each_partitions_sector_counts() {
        let disk = Arc::new(TestDevice(BioRequestSingleQueue::new()));
        let first = TestPartition { disk: disk.clone(), stats: Arc::new(crate::stats::IoStats::new()) };
        let second = TestPartition { disk: disk.clone(), stats: Arc::new(crate::stats::IoStats::new()) };
        let mut batch = IoBatch::new();
        for (partition, sector) in [(&first, 0), (&second, 8), (&first, 16)] {
            let segment = BioSegment::alloc(1, BioDirection::FromDevice);
            Bio::new(BioType::Read, Sid::new(sector), vec![segment], None)
                .submit(partition, &mut batch).unwrap();
        }
        assert_eq!(disk.0.io_stats().in_flight, 1);
        assert_eq!(first.stats.snapshot().in_flight, 1);
        assert_eq!(second.stats.snapshot().in_flight, 1);
        disk.0.dequeue().complete(BioStatus::Complete);
        let disk_stats = disk.0.io_stats();
        let first_stats = first.stats.snapshot();
        let second_stats = second.stats.snapshot();
        assert_eq!((disk_stats.reads, disk_stats.reads_merged, disk_stats.sectors_read), (1, 2, 24));
        assert_eq!((first_stats.reads, first_stats.reads_merged, first_stats.sectors_read), (1, 1, 16));
        assert_eq!((second_stats.reads, second_stats.reads_merged, second_stats.sectors_read), (1, 0, 8));
        assert_eq!(first_stats.in_flight + second_stats.in_flight + disk_stats.in_flight, 0);
    }
}
