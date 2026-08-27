# GitMesh Architecture

Source of truth for layout, build, and protocol. `AGENTS.md` does not duplicate this.

## Overview
Single C11 binary (`./gitmesh`). No Git dependency, no server, no DB.
Flow: UDP broadcast discovery → TCP direct transfer → local index diff.

## Source layout
```
src/common/gitmesh.h               shared types, constants, public API
src/util.c                         helpers (hex, file I/O, atomic write, time)
src/identity.c                     device keypair, known_peers TOFU, user/device names
src/discovery.c                    UDP broadcast announce/probe
src/index.c                        project scan, BLAKE2b hashes, manifest diff, .gitmesh/index
src/proto.c                        TCP session: X25519 kx, secretstream, mutual Ed25519 auth
src/sync.c                         push/pull flows + server-side session handler
src/main.c                         CLI dispatch (peers/share/status/send/receive/name/device/export/import)
src/platform.h                     dispatch header
src/platforms/{darwin,linux,win32}/ per-OS shims (mtime, sockets, dirs)
Makefile                           build, platform detection, deps
tests/run.sh                       loopback e2e test (two fake HOMEs, GITMESH_TCP_PORT)
```

## Build
- `Makefile` detects platform via `uname`/`OS` and sets `PLATFORM` + `CFLAGS -Isrc/platforms/$(PLATFORM)`.
- `CC ?= cc`, `CFLAGS -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE`.
- Deps: `libsodium` (`-lsodium`), `lz4` (`-llz4`); Windows adds `-lws2_32`.
- Outputs: `gitmesh` (or `gitmesh.exe` on Windows).

## Runtime files
- `~/.gitmesh/identity` — 32-byte seed hex, derives `sign_pk/sk` (Ed25519) + `kx_pk/sk` (X25519)
- `~/.gitmesh/user` / `~/.gitmesh/device` — separate names; display is `user@device` (migrates legacy `name`)
- `~/.gitmesh/known_peers` — TOFU pinning: `hex(pk) name` per line
- `<project>/.gitmesh/index` — binary manifest `{count, [path_len, path, hash, size, mtime]}` sorted by path
- `<project>/.gitmesh/tmp/` — temp files for atomic receive

## Constants (src/common/gitmesh.h)
- `GM_VERSION 0.1.0`, `GM_PROTO_VERSION 1`, `GM_MAGIC "GITMESH1"`
- Ports: `GM_DISCO_PORT 42997` (UDP), `GM_TCP_PORT 42998` (TCP, override via `GITMESH_TCP_PORT`/`GITMESH_PORT`/`GM_TCP_PORT`)
- Limits: `GM_NAME_MAX 64`, `GM_PATH_MAX 4096`, `GM_CHUNK 64*1024`, `GM_FRAME_MAX 4 MiB`

## Discovery (UDP)
- Packet: `8B magic + 1B kind (1=ANNOUNCE 2=PROBE) + 2B tcp_port LE + 64B display + 32B sign_pk` = 107B.
- `gm_disco_run` broadcasts ANNOUNCE. `gm_disco_collect` broadcasts PROBE, collects ANNOUNCE replies for N ms, dedupes by `sign_pk`, ignores self.
- `gm_disco_resolve` matches by full display, user prefix, or device suffix (case-insensitive). `ip:port` strings bypass discovery.

## Transport & auth (TCP)
- HELLO: `2B proto_version + 64B display + 32B sign_pk + 32B kx_pk` (cleartext).
- KX: `crypto_kx_client/server_session_keys` → `tx_key`/`rx_key`.
- Secretstream: `init_push`/`init_pull` exchange header; all further frames are `crypto_secretstream_xchacha20poly1305`.
- Mutual auth inside stream: server sends 32B random challenge → client signs `GM1 || challenge || client_kx_pk || server_kx_pk`; server verifies with `peer_sign_pk`, then signs same transcript. `GM_ERR` on failure.
- Framing: `4B wire_len + secretstream(cipher)` where plaintext is `1B type + 4B len + payload`. Types: `GM_GET_MANIFEST 5`, `GM_PUSH_MANIFEST 6`, `GM_SYNC_PLAN 7`, `GM_WANT 8`, `GM_FILE_HDR 9`, `GM_FILE_DATA 10`, `GM_DONE 11`, `GM_ERR 12`, `GM_MANIFEST 13`; handshake-internal `HP_HELLO 30`, `HP_CHALLENGE 31`, `HP_AUTH 32`.

## Sync flows
- **Send (push)**: scan → diff → confirm → connect → `GM_PUSH_MANIFEST(peer_manifest)` → receive `GM_SYNC_PLAN(want[], del[], conflict[])` → stream `GM_FILE_HDR` + `GM_FILE_DATA` chunks (LZ4 if smaller, header `1B flag + 4B clen + data`) → `GM_DONE`. Receiver validates paths, hashes, atomic-rename, merges index.
- **Receive (pull)**: connect → `GM_GET_MANIFEST` → get peer manifest → local `plan_compute` → confirm → `GM_WANT(indices)` → `recv_files` → apply deletes + merge index.
- **Share**: loop: `gm_disco_run` every 2s + `select` on listen fd → `gm_serve` → dispatch `GM_GET_MANIFEST` or `GM_PUSH_MANIFEST`.
- Plan logic (`plan_compute`): want if peer hash differs and local file is unchanged since last index; otherwise conflict. Delete if peer lacks file and local file unchanged; otherwise conflict. `valid_rel_path` rejects `..`, `/`, `\`.

## Index & diff
- `gm_scan` walks project tree (ignores `.git`, `.gitmesh`, `node_modules`, `target`, `dist`, `build`, `__pycache__`, `.DS_Store`, `.pyc`), uses `mtime+size` fast-path vs `old` manifest, else `crypto_generichash` (BLAKE2b-256).
- `gm_index_load/save` binary format with `mtime`; sorted for binary-search `gm_manifest_find` and `gm_diff` (added/modified/deleted counts).
- Index saved only after successful transfer.

## Platform abstraction
`src/platform.h` includes `platforms/<os>/platform.h`. Shims provide `gm_sock_init/close`, `gm_st_mtime_ms`, `mkdir` mapping, `MSG_NOSIGNAL` fallback, `GM_HAVE_REUSEPORT`. Windows uses Winsock (`WSAStartup`), `stat` not `lstat`.
