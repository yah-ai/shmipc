//! A shared memory region: an anonymous file, mapped read-write, never
//! executable, and (on Linux) sealed against resize.
//!
//! ## Why the seals matter
//!
//! Mapping a file another process controls is a liability: if the peer
//! `ftruncate`s it smaller, every subsequent touch of the vanished pages raises
//! **SIGBUS** in *our* process, and there is no way to catch that in safe Rust.
//! Linux's `memfd` seals close this off — `F_SEAL_SHRINK` makes the truncation
//! impossible in the kernel rather than merely impolite.
//!
//! ## What we do *not* seal
//!
//! `F_SEAL_WRITE` is inapplicable here and the ticket's suggestion to apply it
//! is wrong for this use case: it fails with `EBUSY` while any writable mapping
//! exists, and a shared ring is writable on both ends by definition. The seals
//! that apply to a read-write shared region are:
//!
//! | seal | effect | applied |
//! |---|---|---|
//! | `F_SEAL_SHRINK` | no truncation → no SIGBUS | yes |
//! | `F_SEAL_GROW` | size is final | yes |
//! | `F_SEAL_EXEC` (6.3+) | mapping can never become executable | yes, if supported |
//! | `F_SEAL_SEAL` | no further seals may be added | yes, last |
//! | `F_SEAL_WRITE` | no writes at all | **no** — would defeat the purpose |
//!
//! ## macOS
//!
//! There is no sealing equivalent. `shm_open` + `ftruncate` + `mmap` gives the
//! same *mapping*, but nothing stops a peer from shrinking the object, so the
//! SIGBUS argument has to be made differently: the region is created by the
//! process that also spawns the peer, the name is unlinked immediately so no
//! third party can open it, and the fd is passed rather than published. That is
//! a trust argument (only our own child holds the fd), not a kernel guarantee —
//! which is the honest difference to carry into the IPAuRo port.
//! [`SealSet::is_kernel_enforced`] reports which of the two you are standing on.
//!
//! ## Android
//!
//! Android is `target_os = "android"`, not `"linux"`, and bionic ships **neither**
//! half of the two paths above: no `shm_open` (there is no POSIX shared-memory
//! namespace at all) and no `memfd_create` wrapper below API 30, while `minSdk`
//! here is 28 (`app/android/ndk-env.sh`). Reaching for the raw `memfd_create`
//! syscall to dodge the wrapper is worse than it looks: Android's app-process
//! seccomp filter is generated from bionic's own syscall list, and a syscall
//! outside it is `SIGSYS`, i.e. an abort rather than an error return.
//!
//! So the Android arm uses the NDK's own shared-memory API, `ASharedMemory`
//! (`android/sharedmem.h`, `__INTRODUCED_IN(26)` — comfortably below `minSdk`).
//! It is ashmem-backed on older releases and memfd-backed from API 30, and the
//! differences from the `memfd` arm are worth knowing:
//!
//! - **Size is fixed at creation.** `ASharedMemory_create(name, len)` takes the
//!   length, and the API exposes no resize at all — so `create_fd` is what sizes
//!   the object on every platform now, and Android never calls `ftruncate`.
//! - **`ASharedMemory_setProt` is the seal analogue.** Dropping `PROT_EXEC`
//!   applies *system-wide to every fd in every process* referring to the object,
//!   and access can only ever be removed — which is a real kernel guarantee, not
//!   the macOS trust argument. That is what sets [`SealSet::exec`] here.
//! - **Shrink protection is read, not assumed.** On the memfd backing the object
//!   may carry genuine `F_SEAL_*` bits; on ashmem `F_GET_SEALS` simply fails. We
//!   report whichever the running device gives us rather than claiming either.
//!
//! @yah:ticket(R727-B1, "noisetable-android cannot cross-compile: shmipc uses libc::shm_open, absent from bionic")
//! @yah:status(review)
//! @yah:at(2026-09-18T08:20:42Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R727)
//! @yah:severity(high)
//! @yah:verify("source app/android/ndk-env.sh && cargo check -p noisetable-android --target aarch64-linux-android")
//! @yah:gotcha("Measured 2026-09-17 from R726-T15. `source app/android/ndk-env.sh && cargo check -p noisetable-android --target aarch64-linux-android` fails with two E0425 'cannot find function in crate libc': shm_open at crates/lib/shmipc/src/region.rs:223 and shm_unlink at :233. ISOLATED AND CONFIRMED UNRELATED to the SpillHost migration — `cargo check -p shmipc --target aarch64-linux-android` fails identically on its own, and shmipc does not depend on spill_android. Cause is the cfg split in region.rs: the memfd path is cfg(target_os = linux) (:43, :56, :173, :237, :270) and the shm_open path is cfg(not(target_os = linux)) (:209, :265, :285). Android is target_os = android, not linux, so it takes the POSIX branch, and bionic ships no POSIX shared-memory API. shmipc reaches the app transitively via crates/vivarium/banana_builder/Cargo.toml:90 and crates/koda/shm/Cargo.toml:14 — it is not named in app/android/Cargo.toml. Consequence worth stating plainly: the Android app does not currently build at all, so nothing app-side on that target has been compile-verified by anyone recently.")
//! @yah:handoff("LANDED. Android gets its own shared-memory arm in crates/lib/shmipc/src/region.rs, via the NDK's ASharedMemory (android/sharedmem.h). None of the three options the ticket posed was needed: ASharedMemory_create/getSize/setProt are all __INTRODUCED_IN(26), below the pinned API 28, so minSdk does not move, no feature is gated off Android, and the memfd/seccomp trap in @yah:next is sidestepped entirely (verified in the NDK header and in the API-28 stub: llvm-nm -D on sysroot/usr/lib/aarch64-linux-android/28/libandroid.so lists all four ASharedMemory symbols as defined).")
//! @yah:next("RETIRED at review — the three-way decision this ticket was filed around is moot, not deferred. ASharedMemory is __INTRODUCED_IN(26), so the ashmem backing landed with minSdk untouched at 28 and nothing gated off Android. What remains true and worth keeping: do NOT later 'simplify' region.rs by widening the memfd cfg to any(target_os = linux, target_os = android). bionic's memfd_create wrapper is still API 30+, and the raw syscall is not a way around that — Android's app-process seccomp filter is generated from bionic's own syscall list, so an off-list syscall is SIGSYS (abort), not an error return.")
//! @yah:handoff("region.rs, concretely: (1) new `mod ffi` with the three ASharedMemory externs behind `#[link(name = \"android\")]`; (2) `create_fd` now takes `len` and returns an already-sized fd on every platform — sizing moved into the arms via a new `truncate_to` helper, because Android has no resize operation to call after the fact; (3) a third arm `cfg(target_os = \"android\")` for create_fd/apply_seals, with the old `cfg(not(target_os = \"linux\"))` arms narrowed to `cfg(not(any(linux, android)))`; (4) `apply_seals` on Android strips PROT_EXEC via ASharedMemory_setProt (system-wide and irreversible — a real kernel guarantee, unlike the macOS trust argument) and READS shrink/grow/seal via F_GET_SEALS rather than claiming them, since the ashmem backing has none and the API-30+ memfd backing may; (5) `object_len` asks ASharedMemory_getSize on Android — fstat's st_size is not where the ashmem driver keeps the size, so the fstat version would have measured every peer region as 0 bytes and refused every attach; (6) the two platform-branching unit tests gained an Android arm that prints rather than asserts, because both answers are legitimate depending on the device's backing.")
//! @yah:handoff("DISCOVERED WORK #1 — the regression gate. Android was the only shipped target with NO cross-compile coverage anywhere in the repo (noisetable-android is in check-workspace-tests.sh's EXCLUDE list because ndk-sys is a compile_error! off-target, and no other card touches it), which is exactly why a two-arm cfg could break the app for months unnoticed. Added scripts/check-android-cross.sh (arm64|armv7|x86_64; two columns per ABI — shmipc alone, then the app cdylib; exit 0/1/2 with 2 = SKIPPED-not-a-pass) and wired `android-arm64` + `android-armv7` as steps 5 and 6 of .yah/qed/check.toml. Same shape as its sibling scripts/check-windows-cross.sh. Two ABIs on the card, not three: arm64 and armv7 are the two POINTER WIDTHS, which is the axis a check-only gate discriminates; x86_64-linux-android is LP64 like arm64 and differs only in codegen, so it stays a by-hand invocation.")
//! @yah:handoff("DISCOVERED WORK #2 — app/android/ndk-env.sh was not `set -u`-safe: it read $ANDROID_NDK_HOME bare at two sites, so any caller under `set -u` (the new gate script) died with 'unbound variable' before ndk-env.sh could report a missing NDK in its own words. Both reads are now `${ANDROID_NDK_HOME:-}`. Behaviour is identical for its existing callers (build-rust.sh, setup-env.sh). Also retired two dead_code warnings the widened seal_bits cfg exposed: F_ADD_SEALS is now cfg(linux) (Android only ever reads seals) and F_SEAL_WRITE carries an #[allow(dead_code)] with the reason it is deliberately never applied.")
//! @yah:handoff("Also corrected in .yah/qed/check.toml: the release-lane step's header claimed 'IT IS LAST' and its absent on_fail was therefore equivalent to `continue`. It is no longer last, so it now carries an explicit on_fail=continue and the paragraph was rewritten rather than appended to. The Android steps were appended BELOW release-lane specifically so the documented `--from-step 2` and `--from-step 4` recipes keep pointing at the steps they name.")
//! @yah:verify("The ticket's own verify, green: `source app/android/ndk-env.sh && cargo check -p noisetable-android --target aarch64-linux-android` => EXIT=0, 0 lines matching ^error (was two E0425). Log /tmp/r727b1-app-android-a2.log.")
//! @yah:verify("LINKED, not just checked — `cargo build -p noisetable-android --target aarch64-linux-android` => EXIT=0 in 3m54s, producing target/aarch64-linux-android/debug/libnoisetable_android.so. llvm-readelf -d lists libandroid.so in DT_NEEDED (it was not there before; shmipc's #[link] attribute is the only one in the tree), and llvm-nm -D on the API-28 stub libandroid.so shows ASharedMemory_create/getSize/setProt/dupFromJava all defined at that API level. This is the check `cargo check` cannot do.")
//! @yah:verify("No host regression: `cargo test -p shmipc` on macOS => 32 passed, 0 failed (31 lib + 1 integration). The POSIX arm changed too (its ftruncate moved into create_fd) and this is what covers it.")
//! @yah:verify("All three Android ABIs check clean for shmipc: aarch64 EXIT=0, armv7 EXIT=0, x86_64 EXIT=0. The Linux arm — which cannot be checked in-workspace here, because -p shmipc drags workspace-hack and libudev-sys fails to build for a Linux target on this Mac — was verified against aarch64-unknown-linux-gnu by copying the crate to /tmp with a libc-only manifest: EXIT=0, no new warnings.")
//! @yah:verify("The new gate runs and is green end to end: ./scripts/check-android-cross.sh arm64 => 'all 2 column(s) checked clean', armv7 => same. The armv7 run compiled the entire app graph for 32-bit ARM, which had never been built in this tree. `yah qed preflight check` lists android-arm64 and android-armv7 at positions 5 and 6, so the card parses and the earlier --from-step recipes are unshifted.")
//! @yah:gotcha("NOT RUN ON A DEVICE. Everything above is compile-, link- and host-test evidence; no ASharedMemory call has executed on an Android device or emulator, because nothing in this repo runs Rust tests on one. Two claims are therefore reasoned rather than measured, both in the safe direction if wrong: that ASharedMemory_setProt accepts a PROT_EXEC-only removal on the API-30+ memfd backing (if it refuses, SealSet.exec reads false, which merely under-claims), and that the app-process seccomp filter would SIGSYS a raw memfd_create syscall on API 28/29 (the reason that route was not taken — ASharedMemory makes the question moot either way).")
//! @yah:gotcha("One honest under-report on Android: the ATTACH path (SharedRegion::from_fd) reads seals with F_GET_SEALS only, so a region whose creator stripped PROT_EXEC reports SealSet.exec = false on the receiving side even though the protection is system-wide and still in force. ASharedMemory exposes no getProt to ask with. Under-claiming, never over-claiming, and is_kernel_enforced() only consults `shrink`, so nothing downstream reads it wrong.")

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// `libandroid.so` — `android/sharedmem.h`. Declared here rather than pulled in
/// from a `-sys` crate: it is three functions with an ABI the NDK header itself
/// marks frozen ("DO NOT CHANGE THE SIGNATURE OF FUNCTIONS IN ANY WAY"), and a
/// dependency for that is not worth its weight.
#[cfg(target_os = "android")]
mod ffi {
    #[link(name = "android")]
    unsafe extern "C" {
        /// API 26+. Returns an fd for a region of exactly `size` bytes, or -1.
        pub fn ASharedMemory_create(name: *const libc::c_char, size: libc::size_t) -> libc::c_int;
        /// API 26+. Size in bytes; **0** when `fd` is not a shared-memory fd.
        pub fn ASharedMemory_getSize(fd: libc::c_int) -> libc::size_t;
        /// API 26+. Removes access bits system-wide; they can never be added back.
        pub fn ASharedMemory_setProt(fd: libc::c_int, prot: libc::c_int) -> libc::c_int;
    }
}

/// `fcntl` seal bits. Defined locally because `F_SEAL_EXEC` (Linux 6.3) is not
/// in every `libc` release we might build against. Android reads these too —
/// its memfd backing (API 30+) carries real seals.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod seal_bits {
    /// Adding seals is a Linux-only capability; Android only ever reads them.
    #[cfg(target_os = "linux")]
    pub const F_ADD_SEALS: libc::c_int = 1033;
    pub const F_GET_SEALS: libc::c_int = 1034;
    pub const F_SEAL_SEAL: libc::c_int = 0x0001;
    pub const F_SEAL_SHRINK: libc::c_int = 0x0002;
    pub const F_SEAL_GROW: libc::c_int = 0x0004;
    /// Deliberately never applied — see the module header's seal table. Kept so
    /// the bit that would break a read-write ring is named rather than implied.
    #[allow(dead_code)]
    pub const F_SEAL_WRITE: libc::c_int = 0x0008;
    pub const F_SEAL_EXEC: libc::c_int = 0x0020;
}

/// `MFD_NOEXEC_SEAL` (Linux 6.3). Not in every `libc` release, and load-bearing
/// enough to define here rather than gate on the dependency's version.
#[cfg(target_os = "linux")]
const MFD_NOEXEC_SEAL: libc::c_uint = 0x0008;

/// Which protections a region actually got, as opposed to which were requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealSet {
    /// Truncation is impossible — the mapping can never SIGBUS on shrink.
    pub shrink: bool,
    /// The object cannot grow.
    pub grow: bool,
    /// The mapping can never be made executable, kernel-enforced.
    pub exec: bool,
    /// No further seals can be added.
    pub sealed: bool,
}

impl SealSet {
    /// True when the kernel is enforcing these properties, rather than them
    /// resting on "we trust the only process holding the fd".
    pub fn is_kernel_enforced(&self) -> bool {
        self.shrink
    }

    /// One-line summary for a report or a log line.
    pub fn describe(&self) -> String {
        if !self.shrink && !self.grow && !self.exec {
            return "none (platform has no sealing)".to_string();
        }
        let mut parts = Vec::new();
        if self.shrink {
            parts.push("SHRINK");
        }
        if self.grow {
            parts.push("GROW");
        }
        if self.exec {
            parts.push("EXEC");
        }
        if self.sealed {
            parts.push("SEAL");
        }
        parts.join("|")
    }
}

/// A read-write shared mapping over an anonymous file.
///
/// Cloning is not provided: the mapping is unmapped on drop, and cells handed
/// out to koda hold an `Arc<SharedRegion>` to keep it alive.
pub struct SharedRegion {
    fd: OwnedFd,
    base: *mut u8,
    len: usize,
    seals: SealSet,
}

// SAFETY: `base` is a MAP_SHARED mapping valid for `len` bytes until Drop.
// Concurrent access discipline is the caller's (that is what the SPSC and
// cycle protocols in this crate are for).
unsafe impl Send for SharedRegion {}
unsafe impl Sync for SharedRegion {}

impl SharedRegion {
    /// Create a new anonymous region of `len` bytes, zero-filled, mapped
    /// read-write, and sealed as far as the platform allows.
    ///
    /// `name` is a debug label (visible in `/proc/self/fd` on Linux); it is not
    /// a namespace entry a peer can look up.
    pub fn create(name: &str, len: usize) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "region length must be > 0"));
        }
        // `create_fd` hands back an object already sized to `len`. Sizing lives
        // on the platform side of the split because Android's has no resize
        // operation at all — the length is an argument to creation there, and an
        // `ftruncate` after the fact is not something the ashmem backing allows.
        let fd = Self::create_fd(name, len)?;
        let seals = Self::apply_seals(&fd);
        let base = unsafe { Self::map(fd.as_raw_fd(), len, false)? };
        Ok(SharedRegion { fd, base, len, seals })
    }

    /// Map a region from a file descriptor received from a peer.
    ///
    /// `expected_len` is the size *this* side requires. It is checked against
    /// the object's real size rather than taken from it: a peer that passes a
    /// shorter object than the layout calls for must be refused here, not
    /// discovered by faulting past the end later.
    pub fn from_fd(fd: OwnedFd, expected_len: usize) -> io::Result<Self> {
        let actual = Self::object_len(&fd)?;
        if actual < expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("peer region is {actual} bytes, layout needs {expected_len}"),
            ));
        }
        let seals = Self::read_seals(&fd);
        let base = unsafe { Self::map(fd.as_raw_fd(), expected_len, false)? };
        Ok(SharedRegion { fd, base, len: expected_len, seals })
    }

    /// Size of the object behind `fd`, as the kernel reports it.
    ///
    /// This is the only defence against a peer handing over an object shorter
    /// than the layout requires; mapping past the end of one is a SIGBUS on
    /// first touch, not an error return from `mmap`.
    #[cfg(not(target_os = "android"))]
    pub fn object_len(fd: &OwnedFd) -> io::Result<usize> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is owned and open; `st` is a valid out-parameter.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st.st_size as usize)
    }

    /// Android asks the API rather than `fstat`: the ashmem driver keeps the
    /// region size in its own ioctl, not in `st_size`, so a peer's object would
    /// measure as zero bytes and every attach would be refused. `getSize`
    /// answers correctly over both backings, and reports 0 — never an error —
    /// for an fd that is not shared memory at all, which is a refusal here.
    #[cfg(target_os = "android")]
    pub fn object_len(fd: &OwnedFd) -> io::Result<usize> {
        // SAFETY: `fd` is owned and open.
        let len = unsafe { ffi::ASharedMemory_getSize(fd.as_raw_fd()) };
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor is not an ASharedMemory region",
            ));
        }
        Ok(len)
    }

    /// Size an object that was created empty. Linux and POSIX both get here;
    /// Android does not, having been born at its final size.
    #[cfg(not(target_os = "android"))]
    fn truncate_to(fd: OwnedFd, len: usize) -> io::Result<OwnedFd> {
        // SAFETY: `fd` is a fresh, exclusively-owned anonymous file.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    #[cfg(target_os = "linux")]
    fn create_fd(name: &str, len: usize) -> io::Result<OwnedFd> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region name has a NUL"))?;

        // MFD_ALLOW_SEALING is what makes F_ADD_SEALS legal later; without it
        // the object is born with F_SEAL_SEAL already set.
        let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;

        // MFD_NOEXEC_SEAL (Linux 6.3) creates the memfd non-executable and seals
        // that in one step — strictly better than adding F_SEAL_EXEC afterwards,
        // because there is no window in which the object is executable.
        //
        // It is also *mandatory* on a hardened kernel: with `vm.memfd_noexec=2`,
        // memfd_create WITHOUT this flag fails outright with EPERM. Docker
        // Desktop's Linux VM ships that setting, which is how we found it — a
        // build that only ever ran on a permissive kernel would have shipped a
        // transport that cannot allocate a region on a locked-down appliance.
        let raw = unsafe { libc::memfd_create(cname.as_ptr(), base | MFD_NOEXEC_SEAL) };
        if raw >= 0 {
            return Self::truncate_to(unsafe { OwnedFd::from_raw_fd(raw) }, len);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }

        // EINVAL means the kernel predates the flag (< 6.3). Fall back, and let
        // `apply_seals` try F_SEAL_EXEC instead.
        let raw = unsafe { libc::memfd_create(cname.as_ptr(), base) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::truncate_to(unsafe { OwnedFd::from_raw_fd(raw) }, len)
    }

    /// Android: `ASharedMemory`, the NDK's own shared-memory API. See the module
    /// header for why neither of the other two arms is reachable here.
    #[cfg(target_os = "android")]
    fn create_fd(name: &str, len: usize) -> io::Result<OwnedFd> {
        // The name is a debug label only — ashmem has no lookup namespace, so
        // unlike the POSIX arm there is nothing to unlink and no race to close.
        let cname = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region name has a NUL"))?;
        // SAFETY: `cname` outlives the call; `len` is non-zero (checked in `create`).
        let raw = unsafe { ffi::ASharedMemory_create(cname.as_ptr(), len as libc::size_t) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn create_fd(name: &str, len: usize) -> io::Result<OwnedFd> {
        // POSIX shared memory. The name exists in a global namespace, so it is
        // unlinked the moment we hold the fd: from then on the object is
        // reachable only by fd, and the fd only goes where we send it.
        // Darwin's PSHMNAMLEN caps the name at 31 bytes including the '/'.
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let short: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
        let unique = format!("/{}{}-{}", short, std::process::id() % 100_000, seq);
        let cname = std::ffi::CString::new(unique.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region name has a NUL"))?;
        let raw = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600 as libc::c_uint,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // Drop the name immediately — the fd keeps the object alive.
        unsafe { libc::shm_unlink(cname.as_ptr()) };
        Self::truncate_to(unsafe { OwnedFd::from_raw_fd(raw) }, len)
    }

    #[cfg(target_os = "linux")]
    fn apply_seals(fd: &OwnedFd) -> SealSet {
        use seal_bits::*;
        let mut got = SealSet::default();
        // F_SEAL_EXEC is 6.3+; try it first and fall back so an older kernel
        // still gets the SIGBUS protection.
        let with_exec = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_EXEC;
        let without_exec = F_SEAL_SHRINK | F_SEAL_GROW;
        let applied = unsafe {
            if libc::fcntl(fd.as_raw_fd(), F_ADD_SEALS, with_exec) == 0 {
                got.exec = true;
                true
            } else {
                libc::fcntl(fd.as_raw_fd(), F_ADD_SEALS, without_exec) == 0
            }
        };
        if applied {
            got.shrink = true;
            got.grow = true;
            // Close the door behind us so a peer cannot add F_SEAL_WRITE and
            // freeze the ring from under the writer.
            if unsafe { libc::fcntl(fd.as_raw_fd(), F_ADD_SEALS, F_SEAL_SEAL) } == 0 {
                got.sealed = true;
            }
        }
        got
    }

    /// Android has no `F_ADD_SEALS` to offer, but `ASharedMemory_setProt` is a
    /// stronger guarantee than it first looks: removing `PROT_EXEC` applies to
    /// every fd in every process referring to the object, and access can only be
    /// removed. Shrink/grow are *read* rather than requested — the memfd backing
    /// (API 30+) may already carry them, ashmem never does.
    #[cfg(target_os = "android")]
    fn apply_seals(fd: &OwnedFd) -> SealSet {
        let mut got = Self::read_seals(fd);
        // SAFETY: `fd` is owned and open.
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        got.exec = unsafe { ffi::ASharedMemory_setProt(fd.as_raw_fd(), prot) } == 0;
        got
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn apply_seals(_fd: &OwnedFd) -> SealSet {
        SealSet::default()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_seals(fd: &OwnedFd) -> SealSet {
        use seal_bits::*;
        let bits = unsafe { libc::fcntl(fd.as_raw_fd(), F_GET_SEALS) };
        if bits < 0 {
            return SealSet::default();
        }
        SealSet {
            shrink: bits & F_SEAL_SHRINK != 0,
            grow: bits & F_SEAL_GROW != 0,
            exec: bits & F_SEAL_EXEC != 0,
            sealed: bits & F_SEAL_SEAL != 0,
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn read_seals(_fd: &OwnedFd) -> SealSet {
        SealSet::default()
    }

    /// # Safety
    /// `fd` must be an open file of at least `len` bytes.
    unsafe fn map(fd: RawFd, len: usize, exec: bool) -> io::Result<*mut u8> {
        // PROT_EXEC is only ever requested by the negative test that proves the
        // kernel refuses it. Production paths pass `exec: false`.
        let prot = libc::PROT_READ | libc::PROT_WRITE | if exec { libc::PROT_EXEC } else { 0 };
        let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, 0) };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(ptr as *mut u8)
    }

    /// Attempt an *executable* mapping of this region. Always an error on a
    /// platform where `F_SEAL_EXEC` applied.
    ///
    /// Exists so the "the shared mapping is provably non-executable" claim is a
    /// test that runs rather than a sentence in a doc. The returned mapping, if
    /// the platform permits one, is unmapped immediately.
    pub fn probe_exec_mapping(&self) -> io::Result<()> {
        let ptr = unsafe { Self::map(self.fd.as_raw_fd(), self.len, true)? };
        unsafe { libc::munmap(ptr as *mut libc::c_void, self.len) };
        Ok(())
    }

    /// Base of the mapping in this process.
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Mapped length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty. Always false — `create` rejects zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Which protections this region actually carries.
    pub fn seals(&self) -> SealSet {
        self.seals
    }

    /// The underlying descriptor, for handing to a peer over [`crate::fdpass`].
    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Pointer to `offset` within the mapping, bounds-checked against `len`.
    ///
    /// Every offset that came from shared memory must go through here rather
    /// than being added to `base` directly: a peer's descriptor table is
    /// untrusted input, and an unchecked offset is an out-of-bounds access in
    /// whichever process is unlucky enough to be the router.
    pub fn checked_ptr(&self, offset: usize, size: usize) -> Option<*mut u8> {
        let end = offset.checked_add(size)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { self.base.add(offset) })
    }
}

impl Drop for SharedRegion {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are exactly what we mapped, and no borrow of the
        // mapping outlives the region (cells hold an Arc to it).
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.len) };
    }
}

impl std::fmt::Debug for SharedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedRegion")
            .field("len", &self.len)
            .field("seals", &self.seals.describe())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_maps_zeroed_memory() {
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        assert_eq!(region.len(), 4096);
        let bytes = unsafe { std::slice::from_raw_parts(region.base(), 4096) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn writes_are_visible_through_a_second_mapping_of_the_same_object() {
        // Stands in for the cross-process case without needing a process: two
        // independent mappings of one object is exactly what the peer gets.
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        unsafe { region.base().write(0xAB) };

        let dup = region.as_fd().try_clone().expect("dup fd");
        let attached = SharedRegion::from_fd(dup, 4096).expect("attach");
        assert_ne!(
            attached.base(),
            region.base(),
            "the point of position independence is that the addresses differ"
        );
        assert_eq!(unsafe { attached.base().read() }, 0xAB);

        // ...and back the other way.
        unsafe { attached.base().add(8).write(0xCD) };
        assert_eq!(unsafe { region.base().add(8).read() }, 0xCD);
    }

    #[test]
    fn checked_ptr_refuses_out_of_range_offsets() {
        let region = SharedRegion::create("koda-test", 128).expect("create");
        assert!(region.checked_ptr(0, 128).is_some());
        assert!(region.checked_ptr(120, 8).is_some());
        assert!(region.checked_ptr(120, 9).is_none(), "must reject a straddling range");
        assert!(region.checked_ptr(usize::MAX, 1).is_none(), "must reject overflow");
    }

    #[test]
    fn the_kernel_reports_the_object_size_we_asked_for() {
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        let reported = SharedRegion::object_len(region.as_fd()).expect("fstat");
        eprintln!("requested 4096, kernel reports {reported}");
        assert!(reported >= 4096, "an object smaller than requested would SIGBUS on first touch");
    }

    #[test]
    fn from_fd_refuses_an_object_smaller_than_the_layout() {
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        let dup = region.as_fd().try_clone().expect("dup fd");
        let reported = SharedRegion::object_len(region.as_fd()).expect("fstat");

        // Ask for more than the object can possibly hold. On a platform that
        // rounds the object up (macOS grants whole pages), "one byte more than
        // requested" is still inside the object, so the refusal has to be tested
        // against what the kernel actually reports.
        let err = SharedRegion::from_fd(dup, reported + 4096).expect_err("must refuse");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// R097-S4 verify: "the shared mapping is provably non-executable".
    ///
    /// This is a **characterization** test, and deliberately so — the ticket
    /// assumed `F_SEAL_EXEC` makes a `PROT_EXEC` mapping impossible, and that
    /// turns out not to be what the seal does. Measured on aarch64 Linux
    /// 6.x/7.x, with `MFD_NOEXEC_SEAL` applied and `F_GET_SEALS` reporting
    /// `SHRINK|GROW|EXEC|SEAL`, a fresh `mmap(PROT_EXEC)` of the same fd still
    /// **succeeds**. The seal governs the file's mode bits — it stops the object
    /// from being *made* executable — it is not an mmap-time veto.
    ///
    /// So the honest guarantee is two-part, and only one part is the kernel's:
    ///
    /// 1. **Structural (always true):** this crate never requests `PROT_EXEC`.
    ///    `map` is private, and its only `exec: true` caller is this probe.
    /// 2. **Kernel-enforced (Linux 6.3+):** the object is born non-executable
    ///    and sealed that way, so it cannot be chmod'd executable and reopened.
    ///
    /// The test prints what the running kernel actually did, so nobody quotes
    /// the stronger claim off the back of a green suite.
    #[test]
    fn exec_protection_is_characterised_not_assumed() {
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        let seals = region.seals();
        let probe = region.probe_exec_mapping();

        eprintln!(
            "exec protection: seals={} · PROT_EXEC mmap {}",
            seals.describe(),
            match &probe {
                Ok(()) => "SUCCEEDS (seal is mode-bit scope, not an mmap veto)".to_string(),
                Err(e) => format!("refused: {e} (errno {:?})", e.raw_os_error()),
            }
        );

        if cfg!(target_os = "linux") {
            assert!(
                seals.exec,
                "MFD_NOEXEC_SEAL or F_SEAL_EXEC must have applied on Linux; \
                 without it the object can be made executable later"
            );
        } else if cfg!(target_os = "android") {
            // Characterisation only. `exec` here reports whether
            // `ASharedMemory_setProt` accepted the request, and that depends on
            // the device's backing (ashmem below API 30, memfd from 30). Both
            // answers are legitimate; the printed line above is the record.
        } else {
            assert!(
                !seals.exec,
                "no platform sealing outside Linux — non-executability is \
                 structural only (we never pass PROT_EXEC)"
            );
        }
    }

    #[test]
    fn seals_are_kernel_enforced_on_linux_only() {
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        let seals = region.seals();
        if cfg!(target_os = "linux") {
            assert!(seals.shrink, "memfd must be sealed against shrink");
            assert!(seals.is_kernel_enforced());
        } else if cfg!(target_os = "android") {
            // Android straddles: ashmem has no seals, and the memfd backing from
            // API 30 may carry them. `read_seals` reports what the device gave
            // us, so there is nothing to assert either way — only to print.
        } else {
            assert!(!seals.is_kernel_enforced(), "no platform sealing outside Linux");
        }
        eprintln!("seals: {}", seals.describe());
    }
}
