//! The rendezvous that puts a cycle boundary in a peer's hands.
//!
//! Three steps, one socket, both sides in this crate so they cannot drift:
//!
//! ```text
//!   owner: listen … accept ── offer_region(fd + 8-byte LE length) ──►  peer: receive_region
//!   owner: await_ready  ◄──────────────── "READY\n" ──────────────────  peer: signal_ready
//! ```
//!
//! The length travels beside the descriptor rather than being read off the
//! object with `fstat`, because the receiver maps exactly what the owner says it
//! created and [`SharedRegion::from_fd`] refuses an object smaller than that.
//! `READY` is the peer's promise that its serve loop is parked on the cycle
//! sequence: an owner that publishes cycles before it would charge the peer's
//! setup (a graph build, a compile) to the first period and call it an xrun.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::fdpass;
use crate::region::SharedRegion;

/// The line a peer writes once it is ready to be cycled.
pub const READY_LINE: &str = "READY";

/// Owner side: hand `region`'s descriptor and its length to the peer on `sock`.
pub fn offer_region(sock: &UnixStream, region: &SharedRegion) -> io::Result<()> {
    fdpass::send_fd(sock, region.as_fd().as_fd(), &(region.len() as u64).to_le_bytes())
}

/// Peer side: receive the descriptor and map the region it names.
///
/// A header of any length other than eight bytes is refused rather than
/// guessed at: the length is the one figure the mapping is sized from.
pub fn receive_region(sock: &UnixStream) -> io::Result<SharedRegion> {
    let mut header = [0u8; 8];
    let (fd, read) = fdpass::recv_fd(sock, &mut header)?;
    if read != header.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("region header was {read} bytes, expected {}", header.len()),
        ));
    }
    let len = usize::try_from(u64::from_le_bytes(header)).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "region length does not fit this address space")
    })?;
    SharedRegion::from_fd(fd, len)
}

/// Peer side: tell the owner the serve loop is parked and cycles may start.
pub fn signal_ready(mut sock: &UnixStream) -> io::Result<()> {
    writeln!(sock, "{READY_LINE}")?;
    sock.flush()
}

/// Owner side: wait up to `timeout` for the peer's [`READY_LINE`].
///
/// Waits with `poll(2)` rather than `SO_RCVTIMEO`, so the socket's own options
/// are never touched — and because macOS refuses `setsockopt` with `EINVAL`
/// on a socket whose peer already hung up, which would report a dead peer as a
/// bad argument. Reads byte by byte up to the newline, so nothing the peer
/// sends after `READY` is swallowed into a buffer this function then drops.
pub fn await_ready(mut sock: &UnixStream, timeout: Duration) -> io::Result<()> {
    const MAX_LINE: usize = 64;
    let deadline = Instant::now() + timeout;
    let mut line = Vec::with_capacity(READY_LINE.len() + 1);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if !poll_readable(sock, left)? {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "peer did not say READY in time"));
        }
        let mut byte = [0u8; 1];
        match sock.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer hung up before READY",
                ));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if line.len() < MAX_LINE => line.push(byte[0]),
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "peer's READY line is too long"));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if line == READY_LINE.as_bytes() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer said {:?}, expected {READY_LINE:?}", String::from_utf8_lossy(&line)),
        ))
    }
}

/// Is `sock` readable (data or hang-up) within `timeout`?
fn poll_readable(sock: &UnixStream, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: sock.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    loop {
        // SAFETY: one valid pollfd, borrowed for the duration of the call.
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n >= 0 {
            return Ok(n > 0);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_and_ready_round_trip_over_a_socket_pair() {
        let (owner, peer) = UnixStream::pair().expect("socketpair");
        let region = SharedRegion::create("shmipc-rdv", 4096).expect("region");
        unsafe { region.base().write(0x5a) };

        offer_region(&owner, &region).expect("offer");
        let mapped = receive_region(&peer).expect("receive");
        assert_eq!(mapped.len(), region.len());
        assert_eq!(unsafe { mapped.base().read() }, 0x5a, "the peer maps the same object");

        signal_ready(&peer).expect("ready");
        await_ready(&owner, Duration::from_secs(5)).expect("owner sees READY");
    }

    #[test]
    fn a_peer_that_hangs_up_is_not_ready() {
        let (owner, peer) = UnixStream::pair().expect("socketpair");
        drop(peer);
        let err = await_ready(&owner, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_silent_peer_times_out_rather_than_hanging_the_owner() {
        let (owner, _peer) = UnixStream::pair().expect("socketpair");
        let err = await_ready(&owner, Duration::from_millis(20)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }
}
