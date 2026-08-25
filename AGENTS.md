# AGENTS.md — GitMesh

Guidance for AI agents working in this repo.

## What this is
Tiny standalone decentralized LAN tool: discover peer → see changes → send/receive.
C11 + libsodium + LZ4. Single binary. No Git dependency, no server, no GUI.

## Hard rules
- NEVER call git, add Git remotes, or wrap Git semantics. GitMesh has its own index.
- No central server, cloud, accounts, continuous sync, DB, Electron. Reject scope creep.
- Keep it aggressively small and modular. One concern per file under `src/`.
- No comments in code unless asked; code should be self-explanatory.

## Layout
```
src/common/gitmesh.h      shared types/constants
src/util.c                helpers, hex, file IO
src/ident.c              device keypair (~/.gitmesh/identity), known-peers TOFU
src/disco.c              UDP broadcast announce/probe (discovery)
src/index.c              project scan, BLAKE2b hashes, manifest diff (.gitmesh/index)
src/proto.c              TCP session: X25519 kx, secretstream enc, mutual Ed25519 auth
src/sync.c               push/pull flows + server-side session handler
src/main.c               CLI dispatch
src/platform/            platform dispatch header
src/platforms/{darwin,linux,win32}/  per-OS shims (mtime, sockets)
docs/                    PRD, CHECKLIST, JOURNEY, CHANGELOG (keep updated)
```

## Build / test
```
make            # build ./gitmesh
make test       # end-to-end loopback test (two fake HOMEs)
```
macOS: `brew install libsodium lz4`. Link flags live in the Makefile; don't add deps casually.

## Conventions
- Wire protocol changes → bump `PROTO_VERSION` in gitmesh.h and note in docs/CHANGELOG.md.
- Crypto: only libsodium high-level APIs (`crypto_kx`, `crypto_secretstream_*`,
  `crypto_sign_*`, `crypto_generichash`). Never hand-roll primitives.
- Any change to behavior/CLI: update docs/CHECKLIST.md + docs/CHANGELOG.md;
  record decisions in docs/JOURNEY.md.
- Security issues (auth bypass, path traversal, unvalidated lengths) = drop caveman style,
  explain clearly, fix first.
