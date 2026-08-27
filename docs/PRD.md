# GitMesh PRD

## One-liner
Tiny standalone decentralized LAN tool for moving project changes between developer machines.

## Goal
> Discover another machine on LAN → see what changed → send/receive changes.

GitMesh must not depend on Git commands, Git remotes, or Git sync semantics.

## Core requirements
- Standalone protocol (no Git)
- No central server, no accounts, no cloud
- Automatic LAN peer discovery (zero-config)
- Stable device identity (keypair-based)
- Direct peer-to-peer transfer
- Works offline except for the local network
- Cross-platform: Windows, macOS, Linux

## CLI surface
```
gitmesh peers             # list online LAN peers
gitmesh share             # announce presence + accept incoming transfers (daemon)
gitmesh status            # identity, project state, pending changes
gitmesh send <peer>       # push local changes to peer (with confirmation)
gitmesh receive <peer>    # pull peer's changes into local project (with confirmation)
```

Example UX:
```
$ gitmesh peers

● macbook        online
● windows-pc     online

$ gitmesh send macbook

Scanning...
42 files changed
12 files added
3 files deleted

Send to macbook? [y/N]
```

Additional identity commands: `name [new]`, `device [new]`, `export`, `import <hex>` (see `ARCHITECTURE.md`).

Targets resolve by `user`, `device`, `user@device`, or direct `ip:port`.

## Change detection
- GitMesh maintains its own lightweight local index (`.gitmesh/index` in the project).
- Never calls Git. Uses file metadata (size/mtime) + content hashing (BLAKE2b-256 via `crypto_generichash`).
- Classifies: added / modified / deleted files.
- Only changed content is transferred.

## Discovery
- Zero-config LAN discovery.
- MVP: UDP broadcast announce/probe on port 42997.
- mDNS optional later upgrade.
- Peers appear automatically; no IPs entered by users.

## Transfer
- Peer-to-peer only, direct TCP between machines (port 42998).
- Encrypted connection (X25519 key exchange + XChaCha20-Poly1305 secretstream).
- Authenticated peer identity (Ed25519 signatures, TOFU pinning).
- Incremental transfer (only missing/changed files via WANT list).
- Content hashing verifies every file end-to-end.
- Compression (LZ4 per chunk when it helps).
- Transfer progress output.
- Interrupted-transfer recovery where practical (temp-file + atomic rename).

## Non-goals (must NOT build)
- Git integration, Git remotes, fetch/push wrappers
- Cloud sync or central server
- Filesystem-wide continuous sync (not Syncthing)
- Complicated configuration
- Database-heavy architecture
- Electron/GUI

## Tech choices
- Language: C11 (single small binary).
- Crypto/hashing: libsodium (Ed25519, X25519, secretstream, BLAKE2b).
- Compression: LZ4.
- Build: plain Makefile.

## MVP scope
discovery → peer identity → change index → direct transfer. Nothing more.
