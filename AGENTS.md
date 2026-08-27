# AGENTS.md — GitMesh

Guidance for AI agents working in this repo.

## What this is
Tiny standalone decentralized LAN tool: discover peer → see changes → send/receive.
C11 + libsodium + LZ4. Single binary. No Git dependency, no server, no GUI.

## Hard rules
- Git is for repo workflow only; GitMesh must not depend on or implement Git.
- No central server, cloud, accounts, continuous sync, DB, or Electron. Reject scope creep.
- Keep it aggressively small and modular.

## Working rules
- Keep changes focused and minimal.
- Follow `docs/CONVENTIONS.md` for naming, file layout, crypto, and wire-protocol rules; `docs/SECURITY.md` for security handling.
- Update docs when behavior changes (see below).

## Docs
- Current (edit in place): `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/DEVELOPMENT.md`, `docs/CONVENTIONS.md`
- Append-only history (never rewrite entries, only append): `docs/CHECKLIST.md`, `docs/JOURNEY.md`, `docs/CHANGELOG.md`
- Layout and build details live in `docs/ARCHITECTURE.md` and `docs/DEVELOPMENT.md`, not here.
