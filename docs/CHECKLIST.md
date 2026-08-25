# GitMesh Checklist

## Core
- [x] Standalone protocol, no Git dependency
- [x] No central server / accounts / cloud
- [x] Automatic LAN discovery (UDP broadcast)
- [ ] mDNS discovery (optional upgrade)
- [x] Stable device identity (Ed25519 keypair persisted at ~/.gitmesh/identity)
- [x] Direct P2P TCP transfer
- [x] Offline-capable except LAN
- [ ] Windows build verified (code has winsock compat path; tested on macOS/Linux)

## CLI
- [x] `gitmesh peers`
- [x] `gitmesh share`
- [x] `gitmesh status`
- [x] `gitmesh send <peer>`
- [x] `gitmesh receive <peer>`
- [x] Confirmation prompt before transfer ([y/N])

## Change detection
- [x] Local index at `<project>/.gitmesh/index`
- [x] Metadata fast-path (mtime+size) with content hash fallback
- [x] added / modified / deleted classification
- [x] Only changed content transferred
- [x] Ignore rules (.git, .gitmesh, node_modules, target, etc.)

## Transfer
- [x] Encrypted connection (X25519 → XChaCha20-Poly1305 secretstream)
- [x] Authenticated peer identity (Ed25519 challenge-response, mutual, TOFU pinning)
- [x] Incremental transfer (WANT list of needed files)
- [x] Content hashing verification per file
- [x] LZ4 compression per file when beneficial
- [x] Transfer progress output
- [x] Interrupted-transfer recovery (temp file + atomic rename, conflict guard)

## Non-goals respected
- [x] No Git integration / remotes / wrappers
- [x] No cloud / central server
- [x] No continuous FS-wide sync
- [x] No complex config
- [x] No database, no GUI

## Quality
- [x] Builds clean on macOS (clang, -Wall -Wextra)
- [ ] CI for Linux/Windows builds
- [x] End-to-end loopback test (push + pull round-trip)
