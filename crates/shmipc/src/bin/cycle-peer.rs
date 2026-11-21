//! Far side of a cycle boundary, as a real process.
//!
//! Used by `tests/cross_process_cycle.rs`. It lives in `shmipc` rather than in
//! `koda-shm` so the audio leg can be measured on the target platform without
//! building a compiler first — which is what makes
//! `scripts/verify-shmipc-linux.sh` finish in under a minute.
//!
//! Usage: `shmipc-cycle-peer <socket-path> <channels> <frames> <cycles>`

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use shmipc::{CyclePeer, Direction, SharedRegion, StreamSpec, fdpass};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: shmipc-cycle-peer <socket-path> <channels> <frames> <cycles>");
        std::process::exit(2);
    }
    if let Err(e) = run(&args[1], &args[2], &args[3], &args[4]) {
        eprintln!("cycle peer failed: {e}");
        std::process::exit(1);
    }
}

fn run(path: &str, channels: &str, frames: &str, cycles: &str) -> Result<(), String> {
    let channels: u32 = channels.parse().map_err(|_| "bad channel count")?;
    let capacity_frames: u32 = frames.parse().map_err(|_| "bad frame count")?;
    let cycles: u32 = cycles.parse().map_err(|_| "bad cycle count")?;

    let mut sock = UnixStream::connect(path).map_err(|e| format!("connect: {e}"))?;

    let mut header = [0u8; 8];
    let (fd, n) = fdpass::recv_fd(&sock, &mut header).map_err(|e| format!("recv_fd: {e}"))?;
    if n != 8 {
        return Err(format!("short header: {n} bytes"));
    }
    let len = u64::from_le_bytes(header) as usize;
    let region = Arc::new(SharedRegion::from_fd(fd, len).map_err(|e| format!("map region: {e}"))?);

    let streams = [
        StreamSpec { stream_id: 1, channels, capacity_frames, direction: Direction::ToPeer },
        StreamSpec { stream_id: 2, channels, capacity_frames, direction: Direction::FromPeer },
    ];
    let mut peer = CyclePeer::attach(region, &streams).map_err(|e| format!("attach: {e}"))?;

    // Tell the host we are ready, so its first measured cycle is not also
    // measuring our startup.
    writeln!(sock, "READY").map_err(|e| format!("ready: {e}"))?;
    sock.flush().ok();

    let mut served = 0u32;
    while served < cycles {
        match peer.serve_one(Duration::from_secs(10), |_info, bufs| {
            // Minimum honest workload: touch every sample in both directions.
            // A no-op callback would measure the handshake without the cache
            // traffic a real DSP peer pays for.
            let input: Vec<f32> = bufs.stream(0).map(|s| s.to_vec()).unwrap_or_default();
            if let Some(out) = bufs.stream(1) {
                for (o, i) in out.iter_mut().zip(input.iter()) {
                    *o = *i * 0.5;
                }
            }
        }) {
            Ok(Some(_)) => served += 1,
            Ok(None) => break, // host asked to stop
            Err(()) => return Err(format!("timed out after {served} cycles")),
        }
    }

    writeln!(sock, "DONE {served}").map_err(|e| format!("done: {e}"))?;
    sock.flush().map_err(|e| format!("flush: {e}"))
}
