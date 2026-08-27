# GitMesh Security

## Model
LAN-only, no central server. Peers authenticate each other; eavesdroppers on LAN should learn nothing. No PKI — trust on first use (TOFU).

## Crypto (libsodium high-level only)
- Identity: 32B seed → `crypto_sign_seed_keypair` (Ed25519) + `crypto_kx_seed_keypair` (X25519). Seed stored hex in `~/.gitmesh/identity`.
- Key exchange: `crypto_kx_client/server_session_keys` (X25519).
- Transport: `crypto_secretstream_xchacha20poly1305` (XChaCha20-Poly1305) with explicit header exchange. All post-handshake messages are framed through it.
- Auth: mutual challenge-response inside the encrypted stream. Transcript is `GM1 || 32B challenge || kx_pks` (both sides), signed with `crypto_sign_detached` and verified with `peer_sign_pk`. Fresh challenge per session.
- Hashing: `crypto_generichash` (BLAKE2b-256) for file content and index.

Allowed primitives are restricted per `docs/CONVENTIONS.md` — no hand-rolled crypto.

## Peer pinning
- First connection to a `sign_pk` appends `hex(pk) name` to `~/.gitmesh/known_peers` (logged to stderr).
- Later sessions `gm_known_check` verifies; server also pins unknown clients. Mismatch is not yet a hard refusal distinct from TOFU — treat `known_peers` as the stable binding and surface mismatches loudly (auth failure path sends `GM_ERR`).

## Transfer integrity
- Per-file BLAKE2b hash in manifest and `GM_FILE_HDR`; `finish_file` re-hashes received bytes and compares before atomic rename.
- `GM_FRAME_MAX 4 MiB` enforced on `wire_len` and `inner_len`; `parse_plan` caps `want_count`.
- Writes via `gm_write_file_atomic` / `src/sync.c:finish_file` → `.gitmesh/tmp` + rename. Interrupted transfer leaves no half-written project files.

## Path traversal & input validation
- `valid_rel_path` (sync.c) rejects empty, absolute (`/`), `..` anywhere, and `\`. Applied to both manifest entries and received `GM_FILE_HDR` paths.
- All length-prefixed fields checked: `path_len`, `wire_len`, `msg_len`, `clen` vs actual buffer size; `path_len < GM_PATH_MAX`.
- Discovery packet fixed 107B, magic `GITMESH1` checked, self `sign_pk` ignored, deduped.
- PROTO_VERSION mismatch → handshake failure.

## What is not yet hardened
- Discovery is unauthenticated broadcast — anyone on LAN can announce. Auth happens at TCP layer; do not trust discovery names without handshake.
- TOFU has no revocation UI; manual edit of `known_peers` is the current removal path.
- Windows Winsock path exists but is not CI-verified (see `CHECKLIST.md`).
- No rate-limiting or DoS mitigation on `share` listener beyond `GM_FRAME_MAX`.

## Contributor notes
- Security handling and wire-version rules live in `docs/CONVENTIONS.md`; dependency policy lives there as well. Do not duplicate them here.
