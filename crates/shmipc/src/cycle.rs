//! The **audio leg**: JACK's `process()` contract across a process boundary.
//!
//! ## Why this is not a ring
//!
//! A free-running SPSC ring costs one block period per crossing, because the
//! consumer can only read what the producer finished writing in the *previous*
//! period. The hub-and-DSP path crosses twice — network in → DSP → device out —
//! so a ring adds two full periods on exactly the path where latency is the
//! product. At 64 frames / 48 kHz that is 2.7 ms of pure structural delay bought
//! for nothing.
//!
//! Cycle participation costs zero periods instead. The host publishes a cycle
//! descriptor, wakes the peer, and the peer processes **in place** in the shared
//! buffers and signals done — all inside the same period the host is already
//! spending. The price is a hard deadline: a peer that misses it xruns the whole
//! graph rather than merely serving a stale value, which is what a ring would
//! do. That trade is not retrofittable, which is why the shape is decided here
//! rather than after a ring is in production.
//!
//! ```text
//!   host:  fill inputs → publish(seq, frames, sample_pos) → wake ──┐
//!                                                                  │  one period
//!   peer:  ← park on cycle_seq … process in place … done_seq=seq ──┤
//!   host:  ← park on done_seq (deadline) … read outputs ───────────┘
//! ```
//!
//! ## Cycle descriptor, not a bare `&[f32]`
//!
//! The boundary carries frame count, stream time, an epoch that bumps on any
//! discontinuity, and an xrun flag, alongside per-stream identity, channel count
//! and sample rate. This is the local-leg projection of ipauro A004's
//! `CanonicalStream` — identity, signal and clock — with the wire-only fields
//! (channel map, QoS, binding, metadata) dropped, since there is no wire.
//! A peer that received only samples could not tell a discontinuity from a
//! silence, or a late cycle from an early one.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::region::SharedRegion;
use crate::wake::{self, WaitResult};

/// `b"KODACYC1"` little-endian.
const CYCLE_MAGIC: u64 = u64::from_le_bytes(*b"KODACYC1");
const CYCLE_VERSION: u32 = 1;

/// Control block size; the stream table starts here.
const TABLE_OFFSET: usize = 128;
/// Audio buffers start on a cache line.
const BUFFER_ALIGN: usize = 64;

/// Transport state, in the control block's `state` word.
const STATE_RUNNING: u32 = 0;
const STATE_STOPPING: u32 = 1;

/// Set in `xrun_flags` when the host gave up waiting for the peer.
pub const XRUN_PEER_LATE: u32 = 1 << 0;

/// The 128-byte control block at the head of the region.
#[repr(C)]
struct CycleControl {
    magic: u64,
    version: u32,
    stream_count: u32,
    /// Bumped by the host to publish a cycle. Peers park on this word.
    cycle_seq: AtomicU32,
    /// Set by the peer to the `cycle_seq` it finished. The host parks on this.
    done_seq: AtomicU32,
    /// Frames valid this cycle.
    frames: AtomicU32,
    /// Sticky flags describing what went wrong; see [`XRUN_PEER_LATE`].
    xrun_flags: AtomicU32,
    /// Stream time at the start of this cycle, in frames.
    sample_pos: AtomicU64,
    /// Bumped on any discontinuity. A peer whose epoch jumped must not assume
    /// its filter state is still meaningful.
    epoch: AtomicU64,
    sample_rate: AtomicU32,
    state: AtomicU32,
    _reserved: [u64; 9],
}

/// Fixed 32-byte stream descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamDesc {
    stream_id: u64,
    offset: u32,
    capacity_frames: u32,
    channels: u32,
    direction: u32,
    sample_format: u32,
    _pad: u32,
}

/// Which way a stream flows across the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Host writes, peer reads — the peer's input.
    ToPeer = 0,
    /// Peer writes, host reads — the peer's output.
    FromPeer = 1,
}

impl Direction {
    fn from_raw(v: u32) -> Option<Self> {
        match v {
            0 => Some(Direction::ToPeer),
            1 => Some(Direction::FromPeer),
            _ => None,
        }
    }
}

/// One stream on the boundary. Both sides declare these independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSpec {
    /// Stable identity of the stream, so a peer knows what it is processing
    /// rather than inferring it from table order.
    pub stream_id: u64,
    /// Interleaved channel count.
    pub channels: u32,
    /// Largest block the host will ever publish. Buffers are sized for this.
    pub capacity_frames: u32,
    pub direction: Direction,
}

impl StreamSpec {
    fn bytes(&self) -> usize {
        self.channels as usize * self.capacity_frames as usize * std::mem::size_of::<f32>()
    }
}

/// What the peer is told about the cycle it is about to process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CycleInfo {
    /// Monotonic cycle number.
    pub seq: u32,
    /// Frames valid this cycle — never more than any stream's capacity.
    pub frames: u32,
    /// Stream time at the start of this cycle.
    pub sample_pos: u64,
    /// Bumps on discontinuity; compare against the previous cycle's value.
    pub epoch: u64,
    pub sample_rate: u32,
}

/// Result of a host cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Peer finished inside the deadline. `latency` is the measured wake→done
    /// round trip, which is the number that has to fit inside a period.
    Completed { latency: Duration },
    /// The deadline expired first. The output buffers hold whatever the peer
    /// managed; the epoch has been bumped and [`XRUN_PEER_LATE`] set.
    Missed { latency: Duration },
}

/// Why attaching to a cycle boundary failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleError {
    TooSmall { have: usize, need: usize },
    BadMagic { found: u64 },
    BadVersion { found: u32, expected: u32 },
    StreamCountMismatch { found: usize, expected: usize },
    StreamMismatch { index: usize },
    StreamOutOfBounds { index: usize, offset: usize, size: usize, region_len: usize },
    /// The table names a direction this version has no meaning for. Distinct
    /// from [`Self::StreamMismatch`] because it is a malformed table rather than
    /// a disagreement with what this side declared — [`peek_streams`] has no
    /// declaration to disagree with and must still be able to refuse.
    UnknownDirection { index: usize, value: u32 },
    /// Sample format other than f32-interleaved (`0`). Same reason as
    /// [`Self::UnknownDirection`]: nothing to compare against, still refusable.
    UnsupportedSampleFormat { index: usize, format: u32 },
}

impl std::fmt::Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CycleError::TooSmall { have, need } => {
                write!(f, "region is {have} bytes, cycle layout needs {need}")
            }
            CycleError::BadMagic { found } => write!(f, "not a cycle boundary (magic {found:#x})"),
            CycleError::BadVersion { found, expected } => {
                write!(f, "cycle version {found}, this build speaks {expected}")
            }
            CycleError::StreamCountMismatch { found, expected } => {
                write!(f, "peer published {found} streams, this side declares {expected}")
            }
            CycleError::StreamMismatch { index } => {
                write!(f, "stream {index} does not match this side's declaration")
            }
            CycleError::StreamOutOfBounds { index, offset, size, region_len } => write!(
                f,
                "stream {index} buffer spans {offset}..{} outside a {region_len}-byte region",
                offset.saturating_add(*size)
            ),
            CycleError::UnknownDirection { index, value } => {
                write!(f, "stream {index} declares direction {value}, which this build cannot read")
            }
            CycleError::UnsupportedSampleFormat { index, format } => {
                write!(f, "stream {index} declares sample format {format}, not f32-interleaved (0)")
            }
        }
    }
}

impl std::error::Error for CycleError {}

/// Shared plumbing for both ends of the boundary.
#[derive(Debug)]
struct Boundary {
    region: Arc<SharedRegion>,
    streams: Vec<StreamDesc>,
}

impl Boundary {
    fn control(&self) -> &CycleControl {
        // SAFETY: validated to exist at offset 0 by create/attach.
        unsafe { &*(self.region.base() as *const CycleControl) }
    }

    /// Buffer for stream `index`, limited to `frames`.
    ///
    /// # Safety
    /// The caller must hold the cycle: the host before publishing (inputs) or
    /// after the peer signalled done (outputs), the peer only between wake and
    /// done. That discipline is what makes the aliasing here sound.
    unsafe fn buffer(&self, index: usize, frames: u32) -> Option<&mut [f32]> {
        let desc = self.streams.get(index)?;
        let frames = frames.min(desc.capacity_frames);
        let count = desc.channels as usize * frames as usize;
        let bytes = count * std::mem::size_of::<f32>();
        let base = self.region.checked_ptr(desc.offset as usize, bytes)?;
        Some(unsafe { std::slice::from_raw_parts_mut(base as *mut f32, count) })
    }
}

/// Bytes a cycle boundary with `streams` requires.
pub fn required_len(streams: &[StreamSpec]) -> usize {
    let mut offset = TABLE_OFFSET + streams.len() * std::mem::size_of::<StreamDesc>();
    for s in streams {
        offset = offset.div_ceil(BUFFER_ALIGN) * BUFFER_ALIGN;
        offset += s.bytes();
    }
    offset.max(TABLE_OFFSET + std::mem::size_of::<StreamDesc>())
}

/// Read and validate the stream table a host published.
///
/// Every descriptor is bounds-checked against the mapping, and every field this
/// build interprets — direction and sample format — is checked for a value it
/// can actually read. That is the safety story; what a peer *declares* never
/// was. `expected` exists to catch a misconfiguration, and
/// [`CyclePeer::attach`] applies it on top of this.
fn read_table(region: &SharedRegion) -> Result<Vec<StreamDesc>, CycleError> {
    if region.len() < TABLE_OFFSET {
        return Err(CycleError::TooSmall { have: region.len(), need: TABLE_OFFSET });
    }
    // SAFETY: bounds checked above.
    let ctl = unsafe { &*(region.base() as *const CycleControl) };
    if ctl.magic != CYCLE_MAGIC {
        return Err(CycleError::BadMagic { found: ctl.magic });
    }
    if ctl.version != CYCLE_VERSION {
        return Err(CycleError::BadVersion { found: ctl.version, expected: CYCLE_VERSION });
    }

    // Bound the table BEFORE allocating for it: `stream_count` is a number a
    // peer read out of shared memory, so a forged one must fail the extent
    // check rather than reserve for itself.
    let count = ctl.stream_count as usize;
    let table_bytes = count * std::mem::size_of::<StreamDesc>();
    if region.checked_ptr(TABLE_OFFSET, table_bytes).is_none() {
        return Err(CycleError::TooSmall { have: region.len(), need: TABLE_OFFSET + table_bytes });
    }

    let mut streams = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: table extent bounds-checked above.
        let desc = unsafe {
            std::ptr::read((region.base().add(TABLE_OFFSET) as *const StreamDesc).add(index))
        };
        if desc.sample_format != 0 {
            return Err(CycleError::UnsupportedSampleFormat {
                index,
                format: desc.sample_format,
            });
        }
        if Direction::from_raw(desc.direction).is_none() {
            return Err(CycleError::UnknownDirection { index, value: desc.direction });
        }
        // Checked rather than `as usize` arithmetic: both factors come out of
        // the region, so their product is a number a peer chose.
        let bytes = (desc.channels as usize)
            .checked_mul(desc.capacity_frames as usize)
            .and_then(|n| n.checked_mul(std::mem::size_of::<f32>()));
        let out_of_bounds = |size| CycleError::StreamOutOfBounds {
            index,
            offset: desc.offset as usize,
            size,
            region_len: region.len(),
        };
        let bytes = bytes.ok_or_else(|| out_of_bounds(usize::MAX))?;
        if region.checked_ptr(desc.offset as usize, bytes).is_none() {
            return Err(out_of_bounds(bytes));
        }
        streams.push(desc);
    }
    Ok(streams)
}

/// A descriptor as the public spec, or `None` for a direction this build cannot
/// read — which [`read_table`] has already refused, so nothing valid is lost.
fn spec_of(desc: &StreamDesc) -> Option<StreamSpec> {
    Some(StreamSpec {
        stream_id: desc.stream_id,
        channels: desc.channels,
        capacity_frames: desc.capacity_frames,
        direction: Direction::from_raw(desc.direction)?,
    })
}

/// Read the stream table a host published, *without* declaring one first.
///
/// [`CyclePeer::attach`] makes a peer state the table it expects and refuses
/// anything else, which is right for a peer that knows its own shape — the
/// far side of a boundary both ends were built for.
///
/// An **attachment** binds to whatever endpoint a clock owner published, and
/// has to read the table before it can name a stream in it. Discovering the
/// channel count and block size beats configuring the peer with a second copy
/// of them, because a second copy can disagree with the first and the failure
/// is a refusal to attach at boot rather than a wrong number anywhere.
/// Validation is unchanged either way: see [`read_table`].
pub fn peek_streams(region: &SharedRegion) -> Result<Vec<StreamSpec>, CycleError> {
    Ok(read_table(region)?.iter().filter_map(spec_of).collect())
}

/// The side that owns the clock and drives cycles — the process holding the
/// audio device.
pub struct CycleHost {
    inner: Boundary,
    seq: u32,
    sample_pos: u64,
}

impl CycleHost {
    /// Create a boundary sized for `streams` and publish the stream table.
    pub fn create(name: &str, sample_rate: u32, streams: &[StreamSpec]) -> io::Result<Self> {
        let len = required_len(streams);
        let region = Arc::new(SharedRegion::create(name, len)?);

        let mut descs = Vec::with_capacity(streams.len());
        let mut offset = TABLE_OFFSET + streams.len() * std::mem::size_of::<StreamDesc>();
        for s in streams {
            offset = offset.div_ceil(BUFFER_ALIGN) * BUFFER_ALIGN;
            descs.push(StreamDesc {
                stream_id: s.stream_id,
                offset: offset as u32,
                capacity_frames: s.capacity_frames,
                channels: s.channels,
                direction: s.direction as u32,
                sample_format: 0, // f32 interleaved
                _pad: 0,
            });
            offset += s.bytes();
        }

        // SAFETY: the region is freshly created, exclusively ours, and sized by
        // `required_len` for exactly these writes.
        unsafe {
            let table = region.base().add(TABLE_OFFSET) as *mut StreamDesc;
            for (i, d) in descs.iter().enumerate() {
                std::ptr::write(table.add(i), *d);
            }
            std::ptr::write(
                region.base() as *mut CycleControl,
                CycleControl {
                    magic: CYCLE_MAGIC,
                    version: CYCLE_VERSION,
                    stream_count: descs.len() as u32,
                    cycle_seq: AtomicU32::new(0),
                    done_seq: AtomicU32::new(0),
                    frames: AtomicU32::new(0),
                    xrun_flags: AtomicU32::new(0),
                    sample_pos: AtomicU64::new(0),
                    epoch: AtomicU64::new(1),
                    sample_rate: AtomicU32::new(sample_rate),
                    state: AtomicU32::new(STATE_RUNNING),
                    _reserved: [0; 9],
                },
            );
        }

        Ok(CycleHost { inner: Boundary { region, streams: descs }, seq: 0, sample_pos: 0 })
    }

    /// The region, to hand its descriptor to the peer.
    pub fn region(&self) -> &Arc<SharedRegion> {
        &self.inner.region
    }

    /// Mutable view of stream `index`'s buffer for `frames` frames.
    ///
    /// Safe on the host because `&mut self` means no cycle is in flight: the
    /// peer only touches buffers between the publish and the done signal, and
    /// both of those happen inside [`run_cycle`](Self::run_cycle).
    pub fn buffer_mut(&mut self, index: usize, frames: u32) -> Option<&mut [f32]> {
        unsafe { self.inner.buffer(index, frames) }
    }

    /// Publish a cycle, wake the peer, and wait for it to finish.
    ///
    /// `deadline` is the period budget. Returning [`CycleOutcome::Missed`] means
    /// the graph xruns — the caller should emit whatever is in the output
    /// buffers (or silence) and carry on; the epoch has already been bumped so
    /// the peer knows its state is suspect.
    pub fn run_cycle(&mut self, frames: u32, deadline: Duration) -> CycleOutcome {
        let ctl = self.inner.control();
        ctl.frames.store(frames, Ordering::Relaxed);
        ctl.sample_pos.store(self.sample_pos, Ordering::Relaxed);

        self.seq = self.seq.wrapping_add(1);
        let target = self.seq;
        let start = Instant::now();
        // Release: the descriptor and the input samples are visible to any peer
        // that observes this sequence number.
        ctl.cycle_seq.store(target, Ordering::Release);
        wake::wake_one(&ctl.cycle_seq);

        loop {
            if ctl.done_seq.load(Ordering::Acquire) == target {
                // Classify on whether the DEADLINE was met, not merely on
                // whether the peer eventually finished. If our own wait
                // overshot — a sleeping wake path can overshoot by
                // milliseconds — the peer's data is here but the host still
                // blew its period, and that is an xrun however punctual the
                // peer was.
                let latency = start.elapsed();
                self.sample_pos += frames as u64;
                if latency <= deadline {
                    return CycleOutcome::Completed { latency };
                }
                ctl.xrun_flags.fetch_or(XRUN_PEER_LATE, Ordering::Relaxed);
                ctl.epoch.fetch_add(1, Ordering::Relaxed);
                return CycleOutcome::Missed { latency };
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                break;
            }
            // Park on done_seq, expecting "not yet target". A spurious return
            // just re-checks the condition above.
            let observed = ctl.done_seq.load(Ordering::Acquire);
            if observed == target {
                continue;
            }
            if wake::wait(&ctl.done_seq, observed, Some(deadline - elapsed)) == WaitResult::TimedOut
            {
                break;
            }
        }

        // Deadline blown. Sticky flag plus an epoch bump: the peer must treat
        // its filter state as stale rather than assume continuity.
        ctl.xrun_flags.fetch_or(XRUN_PEER_LATE, Ordering::Relaxed);
        ctl.epoch.fetch_add(1, Ordering::Relaxed);
        self.sample_pos += frames as u64;
        CycleOutcome::Missed { latency: start.elapsed() }
    }

    /// Declare a discontinuity the peer did not cause: the next cycle's epoch
    /// differs from the last one it saw.
    ///
    /// A missed deadline bumps the epoch by itself. This is for everything
    /// else the owner knows and the peer cannot infer from samples: the period
    /// changed (the peer must re-prepare for a different block), the device
    /// under the owner was swapped, the stream was re-routed. Call it between
    /// cycles; the bump is published with the next [`run_cycle`](Self::run_cycle).
    pub fn mark_discontinuity(&mut self) {
        self.inner.control().epoch.fetch_add(1, Ordering::Relaxed);
    }

    /// The epoch the next cycle will carry.
    pub fn epoch(&self) -> u64 {
        self.inner.control().epoch.load(Ordering::Relaxed)
    }

    /// Accumulated xrun flags.
    pub fn xrun_flags(&self) -> u32 {
        self.inner.control().xrun_flags.load(Ordering::Relaxed)
    }

    /// Tell the peer to stop and release it from its park.
    pub fn stop(&mut self) {
        let ctl = self.inner.control();
        ctl.state.store(STATE_STOPPING, Ordering::Release);
        self.seq = self.seq.wrapping_add(1);
        ctl.cycle_seq.store(self.seq, Ordering::Release);
        wake::wake(&ctl.cycle_seq, u32::MAX);
    }
}

/// The side that processes cycles it is handed — the out-of-process DSP or
/// device bridge.
#[derive(Debug)]
pub struct CyclePeer {
    inner: Boundary,
    last_seen: u32,
}

impl CyclePeer {
    /// Attach to a host's boundary, validating it against `expected`.
    ///
    /// Everything read out of the region is checked: the stream table's offsets
    /// against the mapping bounds, and its shape against this side's own
    /// declaration. A peer is not entitled to tell us how many bytes to touch.
    pub fn attach(region: Arc<SharedRegion>, expected: &[StreamSpec]) -> Result<Self, CycleError> {
        let streams = read_table(&region)?;
        if streams.len() != expected.len() {
            return Err(CycleError::StreamCountMismatch {
                found: streams.len(),
                expected: expected.len(),
            });
        }
        for (i, (desc, spec)) in streams.iter().zip(expected).enumerate() {
            if desc.stream_id != spec.stream_id
                || desc.channels != spec.channels
                || desc.capacity_frames != spec.capacity_frames
                || Direction::from_raw(desc.direction) != Some(spec.direction)
            {
                return Err(CycleError::StreamMismatch { index: i });
            }
        }

        // SAFETY: `read_table` validated magic, version and extent at offset 0.
        let ctl = unsafe { &*(region.base() as *const CycleControl) };
        let last_seen = ctl.cycle_seq.load(Ordering::Acquire);
        Ok(CyclePeer { inner: Boundary { region, streams }, last_seen })
    }

    /// The boundary's declared sample rate, readable before the first cycle.
    ///
    /// [`CycleInfo`] carries the same figure, but only from inside
    /// [`serve_one`](Self::serve_one) — and an audio attachment has to size its
    /// port at attach time, before any cycle has been published.
    pub fn sample_rate(&self) -> u32 {
        self.inner.control().sample_rate.load(Ordering::Relaxed)
    }

    /// The stream table this peer attached to, in table order.
    pub fn streams(&self) -> Vec<StreamSpec> {
        self.inner.streams.iter().filter_map(spec_of).collect()
    }

    /// Wait for the next cycle, run `process` in place, and signal done.
    ///
    /// Returns `Ok(None)` when the host asked to stop, or `Err(())` on timeout.
    /// `process` runs inside the host's period — it must not allocate, lock, or
    /// do anything else it would not do in a `process()` callback.
    pub fn serve_one<F>(&mut self, timeout: Duration, process: F) -> Result<Option<CycleInfo>, ()>
    where
        F: FnOnce(&CycleInfo, &mut CycleBuffers<'_>),
    {
        let start = Instant::now();
        let seq = loop {
            let ctl = self.inner.control();
            let seq = ctl.cycle_seq.load(Ordering::Acquire);
            if seq != self.last_seen {
                break seq;
            }
            let remaining = timeout.checked_sub(start.elapsed()).ok_or(())?;
            if wake::wait(&ctl.cycle_seq, seq, Some(remaining)) == WaitResult::TimedOut {
                return Err(());
            }
        };
        self.last_seen = seq;

        let ctl = self.inner.control();
        if ctl.state.load(Ordering::Acquire) == STATE_STOPPING {
            return Ok(None);
        }

        let info = CycleInfo {
            seq,
            frames: ctl.frames.load(Ordering::Relaxed),
            sample_pos: ctl.sample_pos.load(Ordering::Relaxed),
            epoch: ctl.epoch.load(Ordering::Relaxed),
            sample_rate: ctl.sample_rate.load(Ordering::Relaxed),
        };

        let mut buffers = CycleBuffers { inner: &self.inner, frames: info.frames };
        process(&info, &mut buffers);

        // Release: the peer's writes are visible to the host that observes this.
        ctl.done_seq.store(seq, Ordering::Release);
        wake::wake_one(&ctl.done_seq);
        Ok(Some(info))
    }
}

/// The in-place buffers for one cycle, handed to the peer's process callback.
pub struct CycleBuffers<'a> {
    inner: &'a Boundary,
    frames: u32,
}

impl CycleBuffers<'_> {
    /// Interleaved samples for stream `index`, `frames` long.
    ///
    /// Both directions are mutable: processing happens **in place**, which is
    /// the whole point — there is no copy into the peer and no copy back.
    pub fn stream(&mut self, index: usize) -> Option<&mut [f32]> {
        // SAFETY: only reachable from inside `serve_one`'s callback, i.e. while
        // the peer holds the cycle and the host is parked waiting for done.
        unsafe { self.inner.buffer(index, self.frames) }
    }

    /// Frames valid this cycle.
    pub fn frames(&self) -> u32 {
        self.frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs() -> Vec<StreamSpec> {
        vec![
            StreamSpec {
                stream_id: 1,
                channels: 2,
                capacity_frames: 64,
                direction: Direction::ToPeer,
            },
            StreamSpec {
                stream_id: 2,
                channels: 2,
                capacity_frames: 64,
                direction: Direction::FromPeer,
            },
        ]
    }

    fn attach_peer(host: &CycleHost) -> CyclePeer {
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));
        CyclePeer::attach(region, &specs()).expect("attach")
    }

    #[test]
    fn control_block_layout_is_stable() {
        assert_eq!(std::mem::size_of::<CycleControl>(), TABLE_OFFSET);
        assert_eq!(std::mem::size_of::<StreamDesc>(), 32);
    }

    /// The defining property: the peer's output for cycle N is available to the
    /// host within cycle N, not cycle N+1.
    #[test]
    fn a_cycle_completes_within_itself() {
        let mut host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let mut peer = attach_peer(&host);

        let worker = std::thread::spawn(move || {
            peer.serve_one(Duration::from_secs(5), |info, bufs| {
                assert_eq!(info.frames, 64);
                // Read the input the host just wrote, and gain it into the output.
                let input: Vec<f32> = bufs.stream(0).unwrap().to_vec();
                let output = bufs.stream(1).unwrap();
                for (o, i) in output.iter_mut().zip(input.iter()) {
                    *o = i * 2.0;
                }
            })
        });

        for (i, s) in host.buffer_mut(0, 64).unwrap().iter_mut().enumerate() {
            *s = i as f32;
        }
        let outcome = host.run_cycle(64, Duration::from_secs(5));
        assert!(matches!(outcome, CycleOutcome::Completed { .. }), "got {outcome:?}");

        // The result is here NOW — not one period later, which is what a ring
        // would have cost.
        let out = host.buffer_mut(1, 64).unwrap();
        assert_eq!(out[0], 0.0);
        assert_eq!(out[1], 2.0);
        assert_eq!(out[127], 254.0);

        worker.join().unwrap().expect("peer served");
        assert_eq!(host.xrun_flags(), 0);
    }

    #[test]
    fn sample_position_advances_by_the_block() {
        let mut host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let mut peer = attach_peer(&host);
        let seen = std::thread::spawn(move || {
            let mut positions = Vec::new();
            for _ in 0..3 {
                let info = peer
                    .serve_one(Duration::from_secs(5), |_, _| {})
                    .expect("served")
                    .expect("running");
                positions.push((info.sample_pos, info.epoch));
            }
            positions
        });

        for _ in 0..3 {
            assert!(matches!(
                host.run_cycle(64, Duration::from_secs(5)),
                CycleOutcome::Completed { .. }
            ));
        }

        let positions = seen.join().unwrap();
        assert_eq!(positions.iter().map(|p| p.0).collect::<Vec<_>>(), vec![0, 64, 128]);
        assert!(positions.iter().all(|p| p.1 == 1), "epoch must be stable while cycles are met");
    }

    /// A period change is the owner's to announce: the peer sees the new frame
    /// count AND a new epoch on the same cycle, so it can tell "re-prepare for
    /// a different block" from "the same block, continued".
    #[test]
    fn a_marked_discontinuity_reaches_the_peer_with_the_next_cycle() {
        let mut host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let mut peer = attach_peer(&host);
        let seen = std::thread::spawn(move || {
            (0..3)
                .map(|_| {
                    let info = peer
                        .serve_one(Duration::from_secs(5), |_, _| {})
                        .expect("served")
                        .expect("running");
                    (info.frames, info.epoch)
                })
                .collect::<Vec<_>>()
        });

        let deadline = Duration::from_secs(5);
        assert!(matches!(host.run_cycle(64, deadline), CycleOutcome::Completed { .. }));
        host.mark_discontinuity();
        assert_eq!(host.epoch(), 2);
        assert!(matches!(host.run_cycle(32, deadline), CycleOutcome::Completed { .. }));
        assert!(matches!(host.run_cycle(32, deadline), CycleOutcome::Completed { .. }));

        assert_eq!(seen.join().unwrap(), vec![(64, 1), (32, 2), (32, 2)]);
    }

    /// A peer that misses the deadline xruns the graph — the host does not
    /// block past its period, and the discontinuity is recorded.
    #[test]
    fn a_late_peer_xruns_rather_than_stalling_the_host() {
        let mut host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let _peer = attach_peer(&host); // attached but never serves

        let start = Instant::now();
        let outcome = host.run_cycle(64, Duration::from_millis(50));
        assert!(matches!(outcome, CycleOutcome::Missed { .. }), "got {outcome:?}");
        assert!(start.elapsed() < Duration::from_secs(1), "host must not block past its deadline");
        assert_eq!(host.xrun_flags() & XRUN_PEER_LATE, XRUN_PEER_LATE);

        // The epoch bump is what tells the peer its state is stale.
        let epoch = host.inner.control().epoch.load(Ordering::Relaxed);
        assert_eq!(epoch, 2, "a missed deadline must bump the epoch");
    }

    #[test]
    fn stop_releases_a_parked_peer() {
        let mut host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let mut peer = attach_peer(&host);
        let worker = std::thread::spawn(move || peer.serve_one(Duration::from_secs(5), |_, _| {}));
        std::thread::sleep(Duration::from_millis(20));
        host.stop();
        assert_eq!(worker.join().unwrap(), Ok(None), "stop must return None, not time out");
    }

    #[test]
    fn attach_refuses_a_stream_table_this_side_does_not_recognise() {
        let host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));

        let mut mine = specs();
        mine[1].channels = 8; // we expect 8 channels where the host published 2
        let err = CyclePeer::attach(region, &mine).expect_err("must refuse");
        assert_eq!(err, CycleError::StreamMismatch { index: 1 });
    }

    /// An attachment that binds to whatever a clock owner published reads the
    /// table instead of declaring it — and then attaches on exactly what it
    /// read, so the two can never disagree.
    #[test]
    fn peek_reports_the_published_table_and_attach_accepts_it() {
        let host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));

        let published = peek_streams(&region).expect("peek");
        assert_eq!(published, specs(), "peek must report what the host published");

        let peer = CyclePeer::attach(region, &published).expect("attach on what was peeked");
        assert_eq!(peer.sample_rate(), 48_000, "the rate is readable before the first cycle");
        assert_eq!(peer.streams(), specs());
    }

    /// `peek_streams` has no declaration to compare against, so its refusals
    /// have to come from the table itself — the same bounds check `attach` runs.
    #[test]
    fn peek_refuses_a_forged_buffer_offset() {
        let host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        unsafe {
            let table = host.region().base().add(TABLE_OFFSET) as *mut StreamDesc;
            (*table).offset = u32::MAX - 16;
        }
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));
        let err = peek_streams(&region).expect_err("must refuse");
        assert!(matches!(err, CycleError::StreamOutOfBounds { index: 0, .. }), "got {err}");
    }

    /// A direction or sample format this build cannot read is a malformed
    /// table, not a disagreement — and there is no `expected` to blame it on.
    #[test]
    fn peek_refuses_a_table_field_this_build_cannot_read() {
        let host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        unsafe {
            let table = host.region().base().add(TABLE_OFFSET) as *mut StreamDesc;
            (*table.add(1)).direction = 7;
        }
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));
        assert_eq!(
            peek_streams(&region).expect_err("must refuse"),
            CycleError::UnknownDirection { index: 1, value: 7 }
        );

        unsafe {
            let table = host.region().base().add(TABLE_OFFSET) as *mut StreamDesc;
            (*table.add(1)).direction = Direction::FromPeer as u32;
            (*table).sample_format = 3;
        }
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));
        assert_eq!(
            peek_streams(&region).expect_err("must refuse"),
            CycleError::UnsupportedSampleFormat { index: 0, format: 3 }
        );
    }

    #[test]
    fn attach_refuses_a_forged_buffer_offset() {
        let host = CycleHost::create("koda-cyc", 48_000, &specs()).expect("create");
        unsafe {
            let table = host.region().base().add(TABLE_OFFSET) as *mut StreamDesc;
            (*table).offset = u32::MAX - 16;
        }
        let dup = host.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, host.region().len()).expect("map"));
        let err = CyclePeer::attach(region, &specs()).expect_err("must refuse");
        assert!(matches!(err, CycleError::StreamOutOfBounds { index: 0, .. }), "got {err}");
    }
}
