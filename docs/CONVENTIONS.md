# GitMesh Conventions

## Code style
- Descriptive names: `peer_count` not `n`, `file_path` not `p`, `content_length` not `len`. Never shorten for convenience.
- One declaration per line; keep locals self-explanatory.
- Short file header (3–9 lines) describing purpose is allowed; otherwise keep code self-explanatory and comment only non-obvious logic.

## Modularity
- One concern per file under `src/`; keep the binary aggressively small.
- No new native dependencies without clear justification (flags live in `Makefile`).

## Crypto
- Only libsodium high-level APIs: `crypto_kx`, `crypto_secretstream_*`, `crypto_sign_*`, `crypto_generichash`. No hand-rolled primitives.

## Wire protocol
- Any wire change → bump `PROTO_VERSION` in `src/common/gitmesh.h` and note in `docs/CHANGELOG.md`.

## Docs
- Behavior/CLI/architecture/security/build changes → update the relevant current doc (`PRD.md`/`ARCHITECTURE.md`/`SECURITY.md`/`DEVELOPMENT.md`) and append to `CHANGELOG.md`; record decisions in `JOURNEY.md`; tick `CHECKLIST.md`.
- See `AGENTS.md` for the current vs append-only doc index; do not duplicate that index here.
