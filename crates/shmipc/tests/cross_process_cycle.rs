//! The audio leg across a real process boundary, measured on whatever platform
//! this runs on.
//!
//! `shmipc`'s unit tests exercise the cycle protocol between two threads. A
//! thread is not a process: it shares an address space, a scheduler group and a
//! page table, so a threaded test cannot tell you what the *boundary* costs.
//! This one spawns `shmipc-cycle-peer` and hands it a descriptor.
//!
//! Deliberately depends on nothing but `shmipc` itself, so
//! `scripts/verify-shmipc-linux.sh` gets the target-platform number (futex wake,
//! sealed memfd) without building a compiler first.
//!
//! ```sh
//! cargo test -p shmipc --release --test cross_process_cycle -- --nocapture
//! ./scripts/verify-shmipc-linux.sh          # same, on aarch64 Linux
//! ```

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command};
use std::time::Duration;

use shmipc::{CycleHost, CycleOutcome, Direction, StreamSpec, fdpass};

const CHANNELS: u32 = 2;
const FRAMES: u32 = 64;
const RATE: u32 = 48_000;
const CYCLES: u32 = 2_000;

struct Child_(Child);

impl Drop for Child_ {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn streams() -> Vec<StreamSpec> {
    vec![
        StreamSpec {
            stream_id: 1,
            channels: CHANNELS,
            capacity_frames: FRAMES,
            direction: Direction::ToPeer,
        },
        StreamSpec {
            stream_id: 2,
            channels: CHANNELS,
            capacity_frames: FRAMES,
            direction: Direction::FromPeer,
        },
    ]
}

#[test]
fn a_cross_process_cycle_fits_inside_a_period() {
    // 64 frames at 48 kHz — the period the whole design is arguing about.
    let period = Duration::from_nanos(FRAMES as u64 * 1_000_000_000 / RATE as u64);
    let specs = streams();
    let mut host = CycleHost::create("shmipc-cyc", RATE, &specs).expect("create host");

    let dir = TempDir(std::env::temp_dir().join(format!("shmipc-cyc-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).expect("mkdir");
    let path = dir.0.join("cyc.sock");
    let listener = UnixListener::bind(&path).expect("bind");

    let child = Child_(
        Command::new(env!("CARGO_BIN_EXE_shmipc-cycle-peer"))
            .arg(&path)
            .arg(CHANNELS.to_string())
            .arg(FRAMES.to_string())
            .arg(CYCLES.to_string())
            .spawn()
            .expect("spawn peer"),
    );

    let (sock, _) = listener.accept().expect("accept");
    sock.set_read_timeout(Some(Duration::from_secs(60))).ok();
    fdpass::send_fd(
        &sock,
        host.region().as_fd().as_fd(),
        &(host.region().len() as u64).to_le_bytes(),
    )
    .expect("send_fd");

    // Wait for the peer to finish attaching, so cycle 1 measures a cycle rather
    // than the child's startup.
    let mut reader = BufReader::new(sock.try_clone().expect("clone"));
    let mut ready = String::new();
    reader.read_line(&mut ready).expect("read READY");
    assert!(ready.starts_with("READY"), "peer said {ready:?}");

    let mut samples = Vec::with_capacity(CYCLES as usize);
    let mut missed = 0u32;
    for c in 0..CYCLES {
        for (i, s) in host.buffer_mut(0, FRAMES).expect("input").iter_mut().enumerate() {
            *s = c as f32 + i as f32;
        }
        match host.run_cycle(FRAMES, period) {
            CycleOutcome::Completed { latency } => samples.push(latency.as_nanos() as u64),
            CycleOutcome::Missed { latency } => {
                missed += 1;
                samples.push(latency.as_nanos() as u64);
            }
        }
    }

    // The defining property: the peer's output for the LAST cycle is readable
    // now, not one period from now. A ring could not make this assertion.
    let out = host.buffer_mut(1, FRAMES).expect("output");
    assert_eq!(out[0], (CYCLES - 1) as f32 * 0.5, "peer must have processed in place");

    host.stop();
    drop(child);

    samples.sort_unstable();
    let p = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    eprintln!(
        "\nplatform: {}\n\
         audio: cross-process cycle {CHANNELS}ch/{FRAMES}f  n={}  \
         p50={:.2}us p99={:.2}us max={:.2}us\n\
         audio: period budget {:.2}us — p99 uses {:.1}% — {missed}/{CYCLES} cycles missed",
        shmipc::platform_capabilities(),
        samples.len(),
        p(0.50) as f64 / 1000.0,
        p(0.99) as f64 / 1000.0,
        samples[samples.len() - 1] as f64 / 1000.0,
        period.as_nanos() as f64 / 1000.0,
        p(0.99) as f64 / period.as_nanos() as f64 * 100.0,
    );

    // Structural, not tuned: if the median cycle ever approaches a period, the
    // design is wrong rather than merely slow, because there would be no room
    // left for the DSP the peer exists to run.
    assert!(
        p(0.50) < period.as_nanos() as u64,
        "median cycle of {}ns does not fit in a {}ns period",
        p(0.50),
        period.as_nanos()
    );
}
