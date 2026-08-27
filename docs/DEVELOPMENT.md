# GitMesh Development

## Prereqs
- C11 compiler (`cc`/`clang`/`gcc`), `make`, `libsodium`, `lz4`.

Install:

```
# macOS
brew install libsodium lz4

# Debian/Ubuntu
sudo apt install libsodium-dev liblz4-dev build-essential

# Windows — MinGW with win32 shim (not yet CI-verified)
# install libsodium + lz4 for your toolchain, then use mingw32-make
```

## Build & test
```
make              # → ./gitmesh (./gitmesh.exe on Windows)
make test         # loopback e2e: two fake HOMEs, GITMESH_TCP_PORT=42999, push/pull + conflicts
make clean
```

`tests/run.sh` uses `HOME=$T/home-*` for isolated identities and `ip:port` targets to bypass broadcast.

## Running locally
```
./gitmesh status          # identity + pending changes in cwd
./gitmesh peers           # scans 2s via UDP broadcast
./gitmesh share           # announce + TCP listener (override: GITMESH_TCP_PORT=42999 ./gitmesh share)
./gitmesh send <peer>     # <peer> = user | device | user@device | ip:port (prompts [y/N])
./gitmesh receive <peer>
```

Identity helpers: `name [new]`, `device [new]`, `export`, `import <hex>`.

## Project conventions
- One concern per file under `src/` (see `ARCHITECTURE.md` for layout).
- See `CONVENTIONS.md` for naming, headers, and doc-update rules.

## Debugging tips
- `GITMESH_TCP_PORT` / `GITMESH_PORT` / `GM_TCP_PORT` env overrides TCP port (useful for parallel tests).
- Two terminals with different `HOME` dirs is the fastest manual loopback without LAN.
- `make` builds with `-Wall -Wextra`; keep it clean.
