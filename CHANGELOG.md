# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased]

### New Features
- `gm8emulator`: Added `-e`/`--encoding` CLI flag (default `windows-1252`). Supported values: `windows-1252` (alias `cp1252`/`latin-1`), `shift-jis` (alias `shift_jis`/`sjis`), `utf-8`. Japanese games should pass `--encoding shift-jis`. (Resolves `M-2`.)
- `COMPATIBILITY.md`: New document tracking games known to work, partially work, or fail under OpenGMK.

### Bug Fixes
- `gm8emulator/src/main.rs`: Runtime error message now correctly goes to stderr (`eprintln!`) instead of stdout.
- `gm8emulator/src/game.rs`: Extension-function load warnings, invalid-MP3 warning, "game ending" diagnostic, and GPU texture-size diagnostic all redirected from stdout to stderr.
- `gm8emulator/src/main.rs`: Temp-dir creation errors now go to stderr (`eprintln!`).
- `gm8emulator/src/gml/kernel.rs`: All 264 `unimplemented!()` panics replaced with logged stubs: `eprintln!(...)` + `Ok(Default::default())`. Games that call unimplemented GML functions now print a warning and continue rather than crashing. (Resolves `H-2`.)
- `gm8emulator/src/gml/kernel.rs` `ord()`: Now accepts lowercase ASCII letters by converting to uppercase before returning the ordinal value, matching GM8 behaviour. (Backport of PR #152.)
- `gm8emulator/src/math.rs`: `Real::PartialEq` and `Real::PartialOrd` now apply GM8's `CMP_EPSILON = 1e-13`, fixing all 7 failing math tests (`lt`, `gt`, `prec_19`, `tan`, `arccos`, `exp`, `op_add`). Exact-order helpers `exact_eq` / `exact_cmp` added for sort and serialisation code. (Resolves `H-1`.)
- `gm8emulator/src/game/gm_save.rs`: Removed `show_windowcol` field from `GMRoomSave` — the field had no corresponding game-state and was never restored by `into_game()`. (Resolves `A-3`.)

### Code Quality
- `gm8emulator/src/render/opengl.rs`: Implemented `Drop` for `RendererImpl`, releasing all OpenGL objects (atlas textures, z-buffers, framebuffers, uniform buffer, VBO, VAO, shader program). `program`, `vao`, `commands_vbo` restored as struct fields (previously commented-out, leaking GPU memory). (Resolves `L-3`.)
- `gm8emulator/src/main.rs`: Temp-dir suffix changed from 5-digit decimal (`% 100000`) to 8-byte / 16-hex-char getrandom output for higher entropy. (Resolves `M-8`.)
- `gm8exe/src/asset/background.rs`, `font.rs`, `object.rs`, `room.rs`, `sprite.rs`: Replaced silent `len as u32` truncating casts with `u32::try_from(...)?` that propagate errors properly. (Resolves `L-1`.)
- `gm8decompiler/src/gmk.rs`: Replaced magic number `800` with named constant `BLOCK_VERSION` throughout. (Resolves `L-2`.)
- `gm8emulator/src/types.rs`: Added comprehensive unit tests for all `From<>` implementations on `Colour`: round-trip `u32`, `(u8,u8,u8)` tuple, `(f64,f64,f64)` tuple, boundary cases (black, white), and `as_hexstring`. (Resolves `L-4`.)
- `gm8emulator/Cargo.toml`: Updated `getrandom` and `indexmap` version-pin comments to explain the constraint reason rather than silently listing an unused newer version. (Resolves `L-9`.)
- `gm8emulator/src/input.rs`: Replaced `// TODO: dont redefine` on `VK_NOKEY`/`VK_ANYKEY` with an explanation of the two-domain design. (Resolves `L-5`.)
- `gm8emulator/src/game/recording.rs`, `recording/control_window.rs`: Fixed typo "occured" → "occurred".
- `gm8decompiler/src/gmk.rs`: Fixed grammar "Writes an Room" → "Writes a Room".

### Documentation
- `README.org`: Updated MSRV claim from 1.59 to 1.77 to match `rust-toolchain.toml`.
- `README.org`: Removed stale `--recurse-submodules` clone instructions (`.gitmodules` is empty; git deps are managed by Cargo).
- `gm8exe/README.md`: Expanded with reader/writer architecture overview, UPX handling, strict-mode description, and a usage example. (Resolves `M-5`.)
- Added `TODO.md`: prioritised work queue synthesised from open issues, PRs, source TODOs, and source analysis.
- Added `APPROVALS.md`: decision queue for items requiring project-owner input (all three decisions resolved).
- Added `CHANGELOG.md`: this file.

### Scripts
- Added `setup.bat` / `setup.ps1`: Windows setup scripts (install toolchain + release build). (Resolves `L-6`.)
- Added `setup.sh`: Linux/macOS setup script.
- Added `run.bat` / `run.ps1` / `run.sh`: platform launch scripts for `gm8emulator`.

---

## Previous Releases

_No prior changelog entries exist. History is available via `git log`._
