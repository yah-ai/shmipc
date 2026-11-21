# yah-shmipc (lib `shmipc`)

Position-independent shared-memory IPC for real-time peers in separate processes.

- `region` — a shared region: sealed `memfd` on Linux (`SHRINK|GROW|EXEC|SEAL`),
  `shm_open` + immediate `shm_unlink` on macOS (no kernel seals; see the module docs).
- `wake` — futex park/wake on Linux, adaptive spin elsewhere.
- `fdpass` — hand the region's descriptor to a peer over `SCM_RIGHTS`.
- `arena` — last-value slots for control traffic (latest state wins, no queue).
- `cycle` — JACK-style cycle participation: the owner publishes a cycle descriptor,
  wakes the peer, the peer processes in place inside the owner's period and signals
  done. Zero added periods; a missed deadline is an xrun, never a block.

Everything read out of a shared region is treated as hostile input: offsets, counts
and tags are bounds-checked against the mapping before use.

Check `shmipc::platform_capabilities()` before quoting a latency number or a safety
property — the Linux and macOS guarantees differ, and the crate says so rather than
papering over it.

Licensed under either of MIT or Apache-2.0 at your option.
