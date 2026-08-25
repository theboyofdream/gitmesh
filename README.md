# GitMesh

Tiny standalone decentralized LAN sync tool: discover peers on your network,
see what changed, send/receive project changes directly. No Git, no server,
no cloud, no accounts.

C11 + libsodium + LZ4. Single small binary.

## How it works

- **Discovery** — periodic UDP broadcast announce/probe on port 42997
- **Transfer** — direct P2P TCP (port 42998), encrypted and authenticated:
  X25519 key exchange → XChaCha20-Poly1305 secretstream → mutual Ed25519
  challenge-response, TOFU peer pinning
- **Change detection** — own binary index at `<project>/.gitmesh/index`,
  BLAKE2b-256 content hashes, mtime+size fast-path rescan
- **Compression** — LZ4 per file when it shrinks the payload

GitMesh never calls Git and has no Git semantics. It tracks files with its
own index.

## Install

macOS deps:

```
brew install libsodium lz4
```

Build:

```
make        # produces ./gitmesh
make test   # end-to-end loopback test with two fake HOMEs
```

Linux needs the same two libraries (`libsodium-dev`, `liblz4-dev`).
Windows builds via the win32 platform shim (not yet CI-verified).

## Usage

On machine A:

```
gitmesh name alice          # set user name (once)
gitmesh share               # announce presence, accept transfers
```

On machine B:

```
gitmesh peers               # see who is online
gitmesh status              # identity + pending local changes
gitmesh send alice          # push changes (shows diff, asks [y/N])
gitmesh receive alice       # pull alice's changes into this project
```

Targets can be a discovered name (`alice`, `alice@m1`, device `m1`) or a
direct `ip:port`.

## Identity

One 32-byte seed per device at `~/.gitmesh/identity`; Ed25519 signing and
X25519 key-exchange keys derive from it. User and device names are separate
(`~/.gitmesh/user`, `~/.gitmesh/device`); display form is `user@device`.

```
gitmesh name [new]          # show/set user name
gitmesh device [new]        # show/set device name
gitmesh export              # print hex seed for backup
gitmesh import <hex>        # restore seed on another device
```

Peers are pinned trust-on-first-use in `~/.gitmesh/known_peers`. A later key
mismatch is refused loudly.

## Safety

- Transfers are end-to-end encrypted and mutually authenticated.
- Received files land via temp file + atomic rename after hash verification;
  an interrupted sync leaves no half-written project files.
- Locally modified files are never silently overwritten — reported as
  conflicts instead.

## Docs

- [docs/PRD.md](docs/PRD.md) — product requirements
- [docs/CHECKLIST.md](docs/CHECKLIST.md) — feature checklist
- [docs/JOURNEY.md](docs/JOURNEY.md) — design decisions and dev log
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — notable changes
- [AGENTS.md](AGENTS.md) — repo layout and conventions for AI agents
