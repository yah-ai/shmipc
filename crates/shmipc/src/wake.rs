//! Blocking on a word inside the shared region.
//!
//! Both legs need the same shape: a peer parks on a 32-bit word until the other
//! side changes it, with no syscall at all in the common case where the value
//! already moved. That is a futex, and it is the same head/tail-plus-futex shape
//! `io_uring` uses.
//!
//! ## Cross-process futexes must not be private
//!
//! `FUTEX_PRIVATE_FLAG` lets the kernel skip resolving the address to its
//! backing page, which is a real speedup — and silently wrong here, because two
//! processes mapping the same page at different virtual addresses would hash to
//! different futex buckets and never see each other's wakeups. The shared
//! variants are the only correct choice for a word in a shared mapping.
//!
//! ## Platforms without a futex
//!
//! macOS has no public process-shared futex before `os_sync_wait_on_address`
//! (14.4), so this falls back to an adaptive spin: `spin_loop` hints, then
//! `sched_yield`, then short sleeps. Correct but not deadline-grade — it burns
//! CPU and its wakeup latency is a scheduler tick, not a microsecond. Anything
//! quoting numbers must say which path it measured; [`HAS_KERNEL_WAIT`] is that
//! flag, and the benchmark prints it.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Whether waiting parks in the kernel (`true`) or spins in userspace (`false`).
pub const HAS_KERNEL_WAIT: bool = cfg!(target_os = "linux");

/// Outcome of a [`wait`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// The word no longer held `expected` — either it had already changed, or a
    /// wake arrived. Re-read the state and proceed.
    Changed,
    /// `timeout` elapsed with the word still at `expected`.
    TimedOut,
}

/// Park until `word` stops being `expected`, or `timeout` elapses.
///
/// Spurious returns of [`WaitResult::Changed`] are permitted and normal — the
/// caller must re-check the condition in a loop, exactly as with a condvar.
pub fn wait(word: &AtomicU32, expected: u32, timeout: Option<Duration>) -> WaitResult {
    if word.load(Ordering::Acquire) != expected {
        return WaitResult::Changed;
    }
    wait_impl(word, expected, timeout)
}

/// Wake up to `count` waiters parked on `word`. Returns how many were woken.
pub fn wake(word: &AtomicU32, count: u32) -> usize {
    wake_impl(word, count)
}

/// Wake a single waiter — the SPSC case, where there is exactly one peer.
pub fn wake_one(word: &AtomicU32) -> usize {
    wake(word, 1)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    const FUTEX_WAIT: libc::c_int = 0;
    const FUTEX_WAKE: libc::c_int = 1;

    pub fn wait_impl(word: &AtomicU32, expected: u32, timeout: Option<Duration>) -> WaitResult {
        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as _,
        });
        let ts_ptr = ts.as_ref().map(|t| t as *const libc::timespec).unwrap_or(std::ptr::null());

        // No FUTEX_PRIVATE_FLAG — see the module docs.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                FUTEX_WAIT,
                expected,
                ts_ptr,
                std::ptr::null::<u32>(),
                0u32,
            )
        };
        if rc == 0 {
            return WaitResult::Changed;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            // The value already differed (EAGAIN) or we were interrupted
            // (EINTR): in both cases the caller re-checks and decides.
            Some(libc::EAGAIN) | Some(libc::EINTR) => WaitResult::Changed,
            Some(libc::ETIMEDOUT) => WaitResult::TimedOut,
            _ => WaitResult::Changed,
        }
    }

    pub fn wake_impl(word: &AtomicU32, count: u32) -> usize {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                FUTEX_WAKE,
                count,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0u32,
            )
        };
        rc.max(0) as usize
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    /// Spin this many times with a pause hint before yielding. Tuned so a
    /// handoff that completes within a few hundred nanoseconds never yields.
    const SPIN_ROUNDS: u32 = 256;
    /// Then yield this many times before sleeping.
    const YIELD_ROUNDS: u32 = 64;
    const SLEEP: Duration = Duration::from_micros(50);

    pub fn wait_impl(word: &AtomicU32, expected: u32, timeout: Option<Duration>) -> WaitResult {
        let start = Instant::now();
        for _ in 0..SPIN_ROUNDS {
            if word.load(Ordering::Acquire) != expected {
                return WaitResult::Changed;
            }
            std::hint::spin_loop();
        }
        for _ in 0..YIELD_ROUNDS {
            if word.load(Ordering::Acquire) != expected {
                return WaitResult::Changed;
            }
            std::thread::yield_now();
        }
        loop {
            if word.load(Ordering::Acquire) != expected {
                return WaitResult::Changed;
            }
            if let Some(limit) = timeout
                && start.elapsed() >= limit
            {
                return WaitResult::TimedOut;
            }
            std::thread::sleep(SLEEP);
        }
    }

    pub fn wake_impl(_word: &AtomicU32, _count: u32) -> usize {
        // Nothing is parked in the kernel; the waiter is polling the word it
        // was told to watch, and the store that preceded this call is the
        // wakeup. Reported as zero woken, which is the truth.
        0
    }
}

use imp::{wait_impl, wake_impl};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn returns_immediately_when_the_value_already_moved() {
        let word = AtomicU32::new(7);
        assert_eq!(wait(&word, 3, Some(Duration::from_secs(5))), WaitResult::Changed);
    }

    #[test]
    fn times_out_when_nothing_happens() {
        let word = AtomicU32::new(0);
        let start = Instant::now();
        assert_eq!(wait(&word, 0, Some(Duration::from_millis(50))), WaitResult::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(40), "must actually wait");
    }

    #[test]
    fn a_writer_releases_a_parked_reader() {
        let word = Arc::new(AtomicU32::new(0));
        let w = Arc::clone(&word);
        let waiter = std::thread::spawn(move || {
            let mut spins = 0;
            while w.load(Ordering::Acquire) == 0 {
                if wait(&w, 0, Some(Duration::from_secs(5))) == WaitResult::TimedOut {
                    return Err("timed out waiting for the writer");
                }
                spins += 1;
                if spins > 10_000 {
                    return Err("spun without progress");
                }
            }
            Ok(w.load(Ordering::Acquire))
        });

        std::thread::sleep(Duration::from_millis(20));
        word.store(42, Ordering::Release);
        wake_one(&word);

        assert_eq!(waiter.join().unwrap(), Ok(42));
    }

    #[test]
    fn reports_which_wait_path_this_build_uses() {
        eprintln!(
            "wake path: {}",
            if HAS_KERNEL_WAIT { "futex (kernel park)" } else { "adaptive spin (userspace)" }
        );
        assert_eq!(HAS_KERNEL_WAIT, cfg!(target_os = "linux"));
    }
}
