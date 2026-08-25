# Changelog

All notable changes. Format loosely based on Keep a Changelog.

## [0.1.0] - 2026-08-25 — MVP

### Added
- `gitmesh peers` — LAN peer discovery via UDP broadcast probe
- `gitmesh share` — presence daemon: periodic announce + TCP transfer listener
- `gitmesh status` — device identity, fingerprint, project index stats, pending changes
- `gitmesh send <peer>` — scan, diff summary, confirm, push incremental changes
- `gitmesh receive <peer>` — inspect peer manifest, confirm, pull incremental changes
- Change engine: local binary index (`.gitmesh/index`), BLAKE2b-256 content hashes,
  mtime+size fast-path rescans, add/modify/delete classification
- Transport: TCP with X25519 ephemeral key exchange, XChaCha20-Poly1305
  secretstream framing, mutual Ed25519 challenge-response auth, TOFU peer pinning
- LZ4 compression per file when it shrinks the payload
- Atomic-write recovery (temp + rename), conflict detection, safe delete policy
- Ignore list (.git, .gitmesh, node_modules, target, dist, build, __pycache__, .DS_Store)
- Cross-platform socket layer (POSIX + Winsock path)

[0.1.0]: https://github.com/example/gitmesh/releases/tag/v0.1.0
