# GitMesh Journey

Dev log — decisions and detours, newest last.

## Day 1 — kickoff
- Goal set: decentralized LAN git-repo sync without Git. Renamed conceptually: not repo sync, **project changes sync**. GitMesh owns its own index.
- Toolchain check: no Rust on machine. User chose **C** instead of Rust. Fine — C keeps binary tiny anyway.
- Dependency scan: Homebrew has libsodium 1.0.20+ and LZ4. Decision: libsodium gives all three crypto needs in one small dep:
  - hashing → BLAKE2b (`crypto_generichash`)
  - identity/auth → Ed25519 sign keypairs
  - transport crypto → X25519 (`crypto_kx`) + `crypto_secretstream_xchacha20poly1305`
  Writing raw crypto by hand rejected — correctness risk not worth zero-dep bragging rights.

## Design decisions
- **Discovery**: spec prefers mDNS but explicitly allows lightweight broadcast fallback. mDNS from scratch in C = wire-format parser + timer state machine ≈ more code than the rest of the tool. MVP ships UDP broadcast announce/probe on one port. mDNS noted as future upgrade. Honest tradeoff: broadcast doesn't cross routers/subnets; fine for dev-LAN use case.
- **Architecture**: both directions are client-initiated. `share` runs the daemon (announce + TCP listener). `send` pushes, `receive` pulls — both connect to the target's listener. Keeps server logic to one session handler.
- **Identity**: one 32-byte seed at `~/.gitmesh/identity`, derive Ed25519 + X25519 keys from it. Peers pinned at `~/.gitmesh/known_peers` trust-on-first-use; key mismatch = loud refusal.
- **Auth**: mutual challenge-response inside the encrypted stream. Both sides sign `challenge || kx_pubs`. No replay (fresh nonce each session).
- **Index**: `.gitmesh/index` binary manifest {path, hash, size, mtime}. Rescan uses mtime+size fast path, rehashes anything suspicious. Index saved only after successful sync so `status` can keep showing pending work.
- **Conflicts**: receiver compares incoming hash vs own current file hash vs own last-synced index entry. Locally-modified files are never silently overwritten → reported as conflicts.
- **Deletes**: applied on receiver only if its index shows the file unmodified since last sync. Otherwise conflict report.
- **Recovery**: files land as `.gitmesh/tmp/<n>` then atomic rename after full receipt + hash match. Interrupted sync leaves no half-written project files.

## Implementation order
util → ident → disco → index → proto → sync → main. Each compiled before next started.

## Testing
Two instances on loopback (different HOME dirs → distinct identities, different ports), push a tree, mutate it, push again, pull from other side. Verified adds/mods/deletes/conflicts + encrypted handshake failure on wrong key.

## Day 1 — polish
- Identity split: `user` (human) vs `device` (box). `~/.gitmesh/user`, `~/.gitmesh/device` separate; display `user@device`. CLI: `name`/`device` get/set, `export`/`import` for seed copy. Announce carries display; discovery resolves by user, device, or full display. Migration: legacy `~/.gitmesh/name` → user.
- Wire fix: uncompressed chunk now carries 4-byte rawlen header consistent with `recv_files` `len==clen+5` check; `LZ4` path unchanged. `GITMESH_TCP_PORT` env override + direct `ip:port` target bypass discovery (loopback test).
- Platform layer moved to `src/platform.h` → `src/platforms/<os>/platform.h`; `src/ident.c`→`identity.c`, `src/disco.c`→`discovery.c` for clarity; Makefile `CFLAGS -Isrc`.
- Sub-agents ran in parallel: proto (auth reply, secretstream arity, listen port), sync (wire, TOFU pin, env), main+discovery (CLI, display).

## Open items
- mDNS (Avahi/Bonjour) behind a flag someday.
- Windows: winsock compat path written, needs real CI run.
- Readability refactor for non-C readers: consistent local naming (plaintext/ciphertext/path_len/result...), one declaration per line. Compiler caught two dropped `gm_scan` args from automated rename — fixed. Decided: struct fields + wire names stay (`sign_pk`, `kx_pk`) since they mirror protocol; only locals renamed. `.clangd` disables misc-include-cleaner because platform.h is a deliberate portability shim.
