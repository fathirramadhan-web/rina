# RINA — Development notes

## Building on Windows

Toolchain quirk: the host Rust toolchain is `x86_64-pc-windows-gnu` but is
missing `dlltool.exe`. The project is compiled against the **MSVC target**
(MSVC BuildTools 2019), which works:

```bash
cargo build -p rina-app --target x86_64-pc-windows-msvc
cargo test --workspace --target x86_64-pc-windows-msvc
```

Tauri's `tauri-build` step also invokes `windres` + `gcc` (to compile
`resource.rc`) even on the MSVC target. These come from MSYS2 mingw-w64, so
prepend it to PATH at build time:

```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
cargo build -p rina-app --target x86_64-pc-windows-msvc
```

If you get `dlltool.exe: program not found` or a `tauri-winres` error about
`windres`/`gcc`, that's this — MSYS2's `binutils` + `gcc` packages must be
installed (`pacman -S mingw-w64-x86_64-binutils mingw-w64-x86_64-gcc`).

## Frontend

```bash
cd apps/rina
npm install
npm run tauri dev      # dev server + Tauri shell with hot reload
npm run build          # tsc + vite -> dist/
```

## Interaction (auth) status

`RinaInteraction` in `apps/rina/src-tauri/src/lib.rs` currently resolves
credentials from environment variables (`RINA_PASSWORD` / `RINA_KEY_PEM`) and
auto-accepts unknown host keys on first use. This is a deliberate
simplification — it must be replaced with real UI dialogs (tauri-plugin-dialog)
and the encrypted vault lookup.
