//! Passing a file descriptor to a peer over a Unix socket (`SCM_RIGHTS`).
//!
//! The alternative — publishing a name in `/dev/shm` and having the peer open
//! it — puts the region in a namespace any process on the box can reach. Passing
//! the descriptor instead means the region is only ever reachable by processes
//! we handed it to, which is the whole access-control story for the local leg.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Send one descriptor plus a small payload over `sock`.
///
/// A byte of payload is mandatory: a `sendmsg` with no data may transfer no
/// control message either.
pub fn send_fd(sock: &UnixStream, fd: BorrowedFd<'_>, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload must be non-empty"));
    }
    let mut iov =
        libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };

    // The control buffer must be CMSG_SPACE(sizeof(int)) and aligned for
    // `cmsghdr`; a `u64` array gives that alignment on every target we build.
    const SPACE: usize = 64;
    let mut cbuf = [0u64; SPACE / 8];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;

    // SAFETY: `msg` is fully initialized above; the cmsg we write fits in cbuf.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("no control header space"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, fd.as_raw_fd());

        let sent = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive one descriptor plus up to `payload.len()` bytes.
///
/// Returns the descriptor and how many payload bytes arrived.
pub fn recv_fd(sock: &UnixStream, payload: &mut [u8]) -> io::Result<(OwnedFd, usize)> {
    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload must be non-empty"));
    }
    let mut iov =
        libc::iovec { iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: payload.len() };
    const SPACE: usize = 64;
    let mut cbuf = [0u64; SPACE / 8];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;

    // SAFETY: `msg` is fully initialized; we only read a cmsg the kernel wrote.
    let received = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed before sending fd"));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("control message truncated — descriptor lost"));
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no descriptor in message"));
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected control message"));
        }
        let raw = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd);
        if raw < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "negative descriptor"));
        }
        Ok((OwnedFd::from_raw_fd(raw), received as usize))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;
    use crate::region::SharedRegion;

    #[test]
    fn round_trips_a_region_descriptor() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let region = SharedRegion::create("koda-test", 4096).expect("create");
        unsafe { region.base().write(0x5A) };

        send_fd(&a, region.as_fd().as_fd(), &(4096u64).to_le_bytes()).expect("send");

        let mut payload = [0u8; 8];
        let (fd, n) = recv_fd(&b, &mut payload).expect("recv");
        assert_eq!(n, 8);
        assert_eq!(u64::from_le_bytes(payload), 4096);

        let attached = SharedRegion::from_fd(fd, 4096).expect("attach");
        assert_eq!(unsafe { attached.base().read() }, 0x5A);
    }

    #[test]
    fn rejects_an_empty_payload() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let region = SharedRegion::create("koda-test", 64).expect("create");
        assert!(send_fd(&a, region.as_fd().as_fd(), &[]).is_err());
    }
}
