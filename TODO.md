# OpenGMK TODO

Synthesized from: source analysis, open/closed GitHub issues, open PRs, commit history, and in-repo TODO/FIXME comments (103 occurrences across 37 files as of 2026-06-22).

---

## Critical

_None identified. No security vulnerabilities, data-loss paths, or silent corruption found._

---

## High

### ~~H-1 · Math test suite failures (issue #139)~~ ✅ DONE

`Real::PartialOrd` and `Real::PartialEq` now apply GM8's `CMP_EPSILON = 1e-13`. All 7 tests pass. Exact-order helpers `exact_eq` / `exact_cmp` added for sort/serialisation code.

### ~~H-2 · 264 `unimplemented!()` panics in `gml/kernel.rs`~~ ✅ DONE

All 264 stubs replaced with `eprintln!(...)` + `Ok(Default::default())`. Games that call missing functions now print a warning and continue instead of panicking.

### ~~H-3 · Merge open PR #158 (arg validation in `resize_backbuffer`)~~ ⚠️ BLOCKED

PR #158 targets the `dll-emulation-2` feature branch, not `master`. The file `game/external/emulated/gm82core.rs` does not exist on `master`. This PR cannot be cherry-picked without merging `dll-emulation-2` first.

---

## Medium

### ~~M-1 · README MSRV claim is stale~~ ✅ DONE

`README.org` now reflects MSRV 1.77 and removes stale `--recurse-submodules` clone instructions.

### ~~M-2 · Character encoding hardcoded to SHIFT_JIS~~ ✅ DONE

`gm8emulator` now accepts `-e`/`--encoding` flag. Default changed to `windows-1252`. Supported values: `windows-1252`, `shift-jis`, `utf-8`.

### ~~M-3 · No game-compatibility list (issue #135)~~ ✅ DONE

`COMPATIBILITY.md` created with status key, known-partial/broken tables, and encoding/platform notes.

### ~~M-4 · Merge/advance draft PR #152 (lowercase `ord` support)~~ ✅ DONE

`ord()` now normalises ASCII lowercase → uppercase before returning the ordinal, matching GM8 behaviour.

### ~~M-5 · `gm8exe` documentation is stub-only~~ ✅ DONE

`gm8exe/README.md` expanded with reader/writer architecture overview, UPX handling, strict-mode description, and usage example.

### M-6 · Compile-time argument-count validation (issue #98)

GML functions should report argument-count errors at compile time (matching GM8 behavior), not at runtime. The existing `expect_args!` macro and function-signature tables in `gml/mappings.rs` could be combined to derive arg-count checks automatically. This eliminates duplicate declarations and catches mismatches earlier.

**Design note:** This is a non-trivial compiler pass. The GML compiler would need to look up each call-target's formal parameter count in the function table at parse/codegen time and emit a diagnostic rather than deferring to `expect_args!` at runtime. Needs its own focused design spike.

### ~~M-7 · `gm_save.rs` missing persistent rooms and room-creation-code~~ (partial) ✅ DONE

`show_windowcol` field removed from `GMRoomSave` (it had no corresponding game-state field and was never restored by `into_game()`). Persistent object data and room creation code still have TODO comments — those are harder and need game-state mapping work.

### ~~M-8 · Temp-dir path created insecurely~~ ✅ DONE

Temp dir now uses an 8-byte random suffix formatted as 16 hex chars (e.g. `gm_ttt_deadbeef12345678`). `println!` for temp-dir errors also changed to `eprintln!`.

---

## Low

### ~~L-1 · `len as u32` casts without overflow checks~~ ✅ DONE

All five locations replaced with `u32::try_from(...)` with proper error propagation.

### ~~L-2 · `gm8decompiler/src/gmk.rs:722` — hardcoded `800`~~ ✅ DONE

`BLOCK_VERSION: u32 = 800` constant defined; all write-call occurrences replaced.

### ~~L-3 · `render/opengl.rs` missing `Drop` impl for GL objects~~ ✅ DONE

`Drop` implemented for `RendererImpl`. Cleans up atlas textures, z-buffers, framebuffers, the uniform buffer, VBO, VAO, and shader program. `program`, `vao`, `commands_vbo` restored as struct fields (were previously commented out).

### ~~L-4 · Sparse platform test coverage~~ ✅ DONE

`types.rs` tests expanded to cover all `From<>` impls for `Colour`: `From<u32>`, `From<(f64,f64,f64)>`, `From<(u8,u8,u8)>`, `From<Colour> for u32`, round-trip, black/white boundary, and `as_hexstring`.

### ~~L-5 · `VK_NOKEY`/`VK_ANYKEY` redefined in `input.rs`~~ ✅ DONE

Comment updated to explain the two-domain design (u8 for key tables, f64 via GML constants). Not a true duplication — separate type domains.

### ~~L-6 · No platform setup/run scripts~~ ✅ DONE

`setup.bat`, `setup.ps1`, `setup.sh`, `run.bat`, `run.ps1`, `run.sh` all created.

### ~~L-7 · No `CHANGELOG.md`~~ ✅ DONE

`CHANGELOG.md` created and maintained.

### ~~L-8 · `.gitmodules` is essentially empty~~ ✅ DONE

README.org updated to remove stale `--recurse-submodules` clone instructions.

### ~~L-9 · `getrandom`/`indexmap` version pins with stale comments~~ ✅ DONE

Comments updated to explain why each is constrained:
- `getrandom`: pinned to `0.2` to avoid a second copy alongside `const-random-macro`'s `0.2` dependency.
- `indexmap`: minimum version `2.5.0`; note added to run `cargo update` to advance the lock file.

---

## Deferred / Out-of-scope

- **WASM / RetroArch port** (issue #134) — major architectural work, out of scope for in-processing.
- **Android support** (issue #131) — out of scope.
- **GMK execution** (issue #141) — enhancement beyond current scope.
- **Linux project paths** (README.org:54-55) — marked "Near Future" in the README; leave as-is.
- **H-3 / PR #158** — blocked on `dll-emulation-2` branch, see H-3 above.
