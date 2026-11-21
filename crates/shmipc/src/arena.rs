//! A table of fixed-size slots inside a shared region — the **control leg**.
//!
//! Control traffic (parameters, device selection, impulses) is variable-rate,
//! latency-insensitive, and tolerant of a dropped intermediate value: the
//! consumer wants the latest state, not every transition. A slot arena serves
//! that directly — each slot is one last-value cell, written by one side and
//! read by the other, with no queue to drain and no backpressure to design.
//!
//! The arena is **domain-free**: it knows sizes, alignments and an opaque `tag`.
//! `koda-shm` puts a koda `SpscElementType` in the tag and hands the slot to
//! `SpscCell::from_foreign`; an audio peer could tag them differently. That is
//! the layering that keeps this crate free of any koda dependency.
//!
//! ## Everything read out of the region is untrusted
//!
//! The descriptor table lives in memory the peer can write. Its offsets are
//! therefore checked against the mapping bounds, and its tags are checked
//! against what the attaching side independently expects — never used to decide
//! how many bytes to touch. A garbage *sample* is bad audio; a garbage *offset*
//! is an out-of-bounds access in whichever process everyone else's data flows
//! through.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::region::SharedRegion;

/// `b"KODASHM1"` little-endian — a mismatch means the peer is not speaking this
/// layout at all, and is refused before anything else is read.
const ARENA_MAGIC: u64 = u64::from_le_bytes(*b"KODASHM1");
const ARENA_VERSION: u32 = 1;

/// Offset of the descriptor table. The header is padded to a cache line so the
/// `ready` word does not share one with the first descriptor.
const TABLE_OFFSET: usize = 64;
/// Slots start on a cache line so two adjacent cells cannot false-share.
const SLOT_ALIGN: usize = 64;

/// Fixed 64-byte arena header.
#[repr(C)]
struct ArenaHeader {
    magic: u64,
    version: u32,
    slot_count: u32,
    total_len: u64,
    /// Set to 1 once the table is fully written. An attaching peer must not
    /// read descriptors before this is 1.
    ready: AtomicU32,
    _pad: u32,
    _reserved: [u64; 4],
}

/// Fixed 16-byte slot descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotDesc {
    offset: u32,
    size: u32,
    tag: u32,
    payload: u32,
}

/// What a slot must be. Both sides declare this independently; attaching
/// compares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotSpec {
    /// Bytes the slot occupies.
    pub size: usize,
    /// Required alignment of the slot's base.
    pub align: usize,
    /// Opaque discriminator — the consumer's notion of "what kind of slot".
    pub tag: u32,
    /// Opaque secondary field, e.g. an element byte size.
    pub payload: u32,
}

/// Why attaching to a peer's arena failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaError {
    /// Region too small to even hold a header.
    TooSmall { have: usize, need: usize },
    /// Not this layout.
    BadMagic { found: u64 },
    /// This layout, different version.
    BadVersion { found: u32, expected: u32 },
    /// The creating side has not finished writing the table.
    NotReady,
    /// Peer declares a different number of slots than this side expects.
    SlotCountMismatch { found: usize, expected: usize },
    /// Slot `index` is not the kind this side expects there.
    SlotMismatch { index: usize, found: SlotSpec, expected: SlotSpec },
    /// Slot `index` points outside the mapping — a hostile or corrupt table.
    SlotOutOfBounds { index: usize, offset: usize, size: usize, region_len: usize },
    /// Slot `index` is not aligned as its spec requires.
    SlotMisaligned { index: usize, align: usize },
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArenaError::TooSmall { have, need } => {
                write!(f, "shared region is {have} bytes, need at least {need}")
            }
            ArenaError::BadMagic { found } => write!(f, "not a slot arena (magic {found:#x})"),
            ArenaError::BadVersion { found, expected } => {
                write!(f, "arena version {found}, this build speaks {expected}")
            }
            ArenaError::NotReady => write!(f, "arena descriptor table is not published yet"),
            ArenaError::SlotCountMismatch { found, expected } => {
                write!(f, "peer published {found} slots, this side declares {expected}")
            }
            ArenaError::SlotMismatch { index, found, expected } => write!(
                f,
                "slot {index}: peer has tag {} size {}, this side declares tag {} size {}",
                found.tag, found.size, expected.tag, expected.size
            ),
            ArenaError::SlotOutOfBounds { index, offset, size, region_len } => write!(
                f,
                "slot {index} spans {offset}..{} outside a {region_len}-byte region",
                offset + size
            ),
            ArenaError::SlotMisaligned { index, align } => {
                write!(f, "slot {index} is not {align}-byte aligned")
            }
        }
    }
}

impl std::error::Error for ArenaError {}

/// A shared region laid out as a table of slots.
pub struct SlotArena {
    region: Arc<SharedRegion>,
    slots: Vec<SlotDesc>,
}

impl SlotArena {
    /// Bytes a region must have to hold `specs`.
    pub fn required_len(specs: &[SlotSpec]) -> usize {
        let mut offset = TABLE_OFFSET + specs.len() * std::mem::size_of::<SlotDesc>();
        for spec in specs {
            let align = spec.align.max(SLOT_ALIGN);
            offset = offset.div_ceil(align) * align;
            offset += spec.size;
        }
        offset.max(TABLE_OFFSET + std::mem::size_of::<SlotDesc>())
    }

    /// Create a region sized for `specs`, lay out the slots, and publish the table.
    pub fn create(name: &str, specs: &[SlotSpec]) -> std::io::Result<Self> {
        let len = Self::required_len(specs);
        let region = Arc::new(SharedRegion::create(name, len)?);
        Ok(Self::lay_out(region, specs))
    }

    /// Lay out and publish `specs` into an existing region.
    ///
    /// # Panics
    /// If `region` is smaller than [`required_len`](Self::required_len).
    pub fn lay_out(region: Arc<SharedRegion>, specs: &[SlotSpec]) -> Self {
        let need = Self::required_len(specs);
        assert!(region.len() >= need, "region {} < required {need}", region.len());

        let mut slots = Vec::with_capacity(specs.len());
        let mut offset = TABLE_OFFSET + specs.len() * std::mem::size_of::<SlotDesc>();
        for spec in specs {
            let align = spec.align.max(SLOT_ALIGN);
            offset = offset.div_ceil(align) * align;
            slots.push(SlotDesc {
                offset: offset as u32,
                size: spec.size as u32,
                tag: spec.tag,
                payload: spec.payload,
            });
            offset += spec.size;
        }

        // SAFETY: the region is freshly created and exclusively ours until the
        // fd is handed to a peer, and every write below is inside `need`.
        unsafe {
            let table = region.base().add(TABLE_OFFSET) as *mut SlotDesc;
            for (i, desc) in slots.iter().enumerate() {
                std::ptr::write(table.add(i), *desc);
            }
            let header = region.base() as *mut ArenaHeader;
            std::ptr::write(
                header,
                ArenaHeader {
                    magic: ARENA_MAGIC,
                    version: ARENA_VERSION,
                    slot_count: slots.len() as u32,
                    total_len: region.len() as u64,
                    ready: AtomicU32::new(0),
                    _pad: 0,
                    _reserved: [0; 4],
                },
            );
            // Release: everything above is visible before `ready` is observed.
            (*header).ready.store(1, Ordering::Release);
        }

        SlotArena { region, slots }
    }

    /// Attach to an arena a peer created, validating it against `expected`.
    ///
    /// `expected` is what *this* side's own declarations call for. Nothing in
    /// the region is allowed to widen it.
    pub fn attach(region: Arc<SharedRegion>, expected: &[SlotSpec]) -> Result<Self, ArenaError> {
        let header_size = std::mem::size_of::<ArenaHeader>();
        if region.len() < TABLE_OFFSET.max(header_size) {
            return Err(ArenaError::TooSmall { have: region.len(), need: TABLE_OFFSET });
        }

        // SAFETY: bounds checked above; the header is plain data.
        let header = unsafe { &*(region.base() as *const ArenaHeader) };
        if header.magic != ARENA_MAGIC {
            return Err(ArenaError::BadMagic { found: header.magic });
        }
        if header.version != ARENA_VERSION {
            return Err(ArenaError::BadVersion { found: header.version, expected: ARENA_VERSION });
        }
        if header.ready.load(Ordering::Acquire) != 1 {
            return Err(ArenaError::NotReady);
        }
        let count = header.slot_count as usize;
        if count != expected.len() {
            return Err(ArenaError::SlotCountMismatch { found: count, expected: expected.len() });
        }

        // The table's own extent must be inside the mapping before it is read.
        let table_bytes = count * std::mem::size_of::<SlotDesc>();
        if region.checked_ptr(TABLE_OFFSET, table_bytes).is_none() {
            return Err(ArenaError::TooSmall {
                have: region.len(),
                need: TABLE_OFFSET + table_bytes,
            });
        }

        let mut slots = Vec::with_capacity(count);
        for (i, spec) in expected.iter().enumerate() {
            // SAFETY: the table's extent was bounds-checked above.
            let desc = unsafe {
                std::ptr::read((region.base().add(TABLE_OFFSET) as *const SlotDesc).add(i))
            };
            let found = SlotSpec {
                size: desc.size as usize,
                align: spec.align,
                tag: desc.tag,
                payload: desc.payload,
            };
            if desc.tag != spec.tag
                || desc.size as usize != spec.size
                || desc.payload != spec.payload
            {
                return Err(ArenaError::SlotMismatch { index: i, found, expected: *spec });
            }
            let offset = desc.offset as usize;
            let base =
                region.checked_ptr(offset, spec.size).ok_or(ArenaError::SlotOutOfBounds {
                    index: i,
                    offset,
                    size: spec.size,
                    region_len: region.len(),
                })?;
            if base as usize % spec.align != 0 {
                return Err(ArenaError::SlotMisaligned { index: i, align: spec.align });
            }
            slots.push(desc);
        }

        Ok(SlotArena { region, slots })
    }

    /// Number of slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the arena has no slots.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The region this arena lives in — clone it to keep the mapping alive for
    /// as long as anything points into a slot.
    pub fn region(&self) -> &Arc<SharedRegion> {
        &self.region
    }

    /// Base pointer of slot `index`, or `None` if there is no such slot.
    ///
    /// Validated at attach time, so this cannot hand out an out-of-bounds
    /// pointer even if the peer rewrote the table afterwards — the offsets were
    /// copied into `self.slots` and re-checked here.
    pub fn slot_ptr(&self, index: usize) -> Option<*mut u8> {
        let desc = self.slots.get(index)?;
        self.region.checked_ptr(desc.offset as usize, desc.size as usize)
    }

    /// Tag recorded for slot `index`.
    pub fn slot_tag(&self, index: usize) -> Option<u32> {
        self.slots.get(index).map(|d| d.tag)
    }
}

impl std::fmt::Debug for SlotArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotArena")
            .field("slots", &self.slots.len())
            .field("region", &self.region)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(size: usize, tag: u32) -> SlotSpec {
        SlotSpec { size, align: 8, tag, payload: size as u32 }
    }

    #[test]
    fn slots_are_disjoint_and_aligned() {
        let specs = [spec(4, 0), spec(24, 4), spec(8, 1)];
        let arena = SlotArena::create("koda-test", &specs).expect("create");

        let mut seen: Vec<(usize, usize)> = Vec::new();
        for (i, s) in specs.iter().enumerate() {
            let p = arena.slot_ptr(i).expect("slot present") as usize;
            assert_eq!(p % s.align, 0, "slot {i} misaligned");
            for (start, end) in &seen {
                assert!(p >= *end || p + s.size <= *start, "slot {i} overlaps an earlier slot");
            }
            seen.push((p, p + s.size));
        }
    }

    #[test]
    fn attach_sees_the_same_slots_at_different_addresses() {
        let specs = [spec(4, 0), spec(24, 4)];
        let arena = SlotArena::create("koda-test", &specs).expect("create");
        unsafe { arena.slot_ptr(0).unwrap().cast::<u32>().write(0xDEADBEEF) };

        let dup = arena.region().as_fd().try_clone().expect("dup");
        let attached_region =
            Arc::new(SharedRegion::from_fd(dup, arena.region().len()).expect("map"));
        let attached = SlotArena::attach(attached_region, &specs).expect("attach");

        assert_ne!(attached.slot_ptr(0).unwrap(), arena.slot_ptr(0).unwrap());
        assert_eq!(unsafe { attached.slot_ptr(0).unwrap().cast::<u32>().read() }, 0xDEADBEEF);
    }

    #[test]
    fn attach_refuses_a_different_slot_shape() {
        let created = [spec(4, 0), spec(24, 4)];
        let arena = SlotArena::create("koda-test", &created).expect("create");
        let dup = arena.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, arena.region().len()).expect("map"));

        // Same count, different tag at index 1 — the peer declares a different
        // element type there than we do.
        let mine = [spec(4, 0), spec(24, 9)];
        let err = SlotArena::attach(region, &mine).expect_err("must refuse");
        assert!(matches!(err, ArenaError::SlotMismatch { index: 1, .. }), "got {err}");
    }

    #[test]
    fn attach_refuses_a_different_slot_count() {
        let arena = SlotArena::create("koda-test", &[spec(4, 0), spec(8, 1)]).expect("create");
        let dup = arena.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, arena.region().len()).expect("map"));
        let err = SlotArena::attach(region, &[spec(4, 0)]).expect_err("must refuse");
        assert_eq!(err, ArenaError::SlotCountMismatch { found: 2, expected: 1 });
    }

    #[test]
    fn attach_refuses_an_unrelated_region() {
        let region = Arc::new(SharedRegion::create("koda-test", 4096).expect("create"));
        let err = SlotArena::attach(region, &[spec(4, 0)]).expect_err("must refuse");
        assert!(matches!(err, ArenaError::BadMagic { .. }), "got {err}");
    }

    /// A peer that rewrites an offset to point outside the mapping must be
    /// caught at attach, not by faulting later.
    #[test]
    fn attach_refuses_an_out_of_bounds_offset() {
        let specs = [spec(4, 0)];
        let arena = SlotArena::create("koda-test", &specs).expect("create");
        // Forge the descriptor the way a buggy or hostile peer would.
        unsafe {
            let table = arena.region().base().add(TABLE_OFFSET) as *mut SlotDesc;
            (*table).offset = u32::MAX - 2;
        }

        let dup = arena.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, arena.region().len()).expect("map"));
        let err = SlotArena::attach(region, &specs).expect_err("must refuse");
        assert!(matches!(err, ArenaError::SlotOutOfBounds { index: 0, .. }), "got {err}");
    }

    #[test]
    fn attach_refuses_an_unpublished_table() {
        let specs = [spec(4, 0)];
        let arena = SlotArena::create("koda-test", &specs).expect("create");
        unsafe {
            (*(arena.region().base() as *const ArenaHeader)).ready.store(0, Ordering::Release);
        }
        let dup = arena.region().as_fd().try_clone().expect("dup");
        let region = Arc::new(SharedRegion::from_fd(dup, arena.region().len()).expect("map"));
        assert_eq!(
            SlotArena::attach(region, &specs).expect_err("must refuse"),
            ArenaError::NotReady
        );
    }

    #[test]
    fn header_layout_is_stable() {
        assert_eq!(std::mem::size_of::<ArenaHeader>(), TABLE_OFFSET);
        assert_eq!(std::mem::size_of::<SlotDesc>(), 16);
    }
}
