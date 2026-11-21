//! Position-independent shared-memory IPC.
//!
//! Built for R097-S4: making a cross-process boundary cheap enough that
//! out-of-process is the default extension model rather than a fallback. A
//! subprocess that segfaults costs a device bridge; an in-process native plugin
//! that segfaults costs the audio thread, and commits us to an ABI contract with
//! third-party code we do not control. This crate is the transport that makes
//! the former affordable. It is **not** a plugin loader and must not grow into
//! one — nothing here should ever `dlopen` anything.
//!
//! ## Two legs, opposite requirements
//!
//! | | control | audio |
//! |---|---|---|
//! | rate | variable, event-driven | fixed, block-aligned |
//! | loss | latest-value wins; drops fine | must not drop |
//! | timing | latency-insensitive | hard deadline |
//! | shape | [`arena`] — last-value slots | [`cycle`] — cycle participation |
//!
//! Validating only the control case would look like success and then be wrong
//! for audio, because a ring's one-period-per-crossing cost is invisible until
//! you put it on the path where latency is the product. The two modules exist
//! separately for that reason.
//!
//! ## Layering
//!
//! Deliberately domain-free — no koda, no vivarium, no audio-engine types. The
//! koda binding (`spsc[T]` backed by a shared slot) lives in `koda-shm`; an
//! audio peer consumes [`cycle`] without either. Slot tags are opaque `u32`s
//! precisely so this crate never learns what a `SpscElementType` is.
//!
//! ## Platform
//!
//! Linux is the target the guarantees are written against: `memfd_create` with
//! seals against truncation, and futex for the wake path. macOS gets the same
//! *shape* (POSIX shm, adaptive spin) with weaker guarantees, spelled out in
//! [`region`] and [`wake`] rather than papered over. Check
//! [`wake::HAS_KERNEL_WAIT`] and [`region::SealSet::is_kernel_enforced`] before
//! quoting any number or any safety property.

pub mod arena;
pub mod cycle;
pub mod fdpass;
pub mod region;
pub mod rendezvous;
pub mod wake;

pub use arena::{ArenaError, SlotArena, SlotSpec};
pub use cycle::{
    CycleBuffers,
    CycleError,
    CycleHost,
    CycleInfo,
    CycleOutcome,
    CyclePeer,
    Direction,
    StreamSpec,
    // The one flag a host reads back off a boundary — re-exported with the
    // types it describes, so reading an outcome does not need a second import
    // path.
    XRUN_PEER_LATE,
    peek_streams,
};
pub use region::{SealSet, SharedRegion};

/// What this build's platform actually provides, for reports and logs.
pub fn platform_capabilities() -> String {
    format!(
        "wake={} seals={}",
        if wake::HAS_KERNEL_WAIT { "futex" } else { "spin" },
        if cfg!(target_os = "linux") { "memfd" } else { "none" },
    )
}
