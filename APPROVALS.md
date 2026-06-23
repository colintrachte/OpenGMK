# APPROVALS — Decisions Awaiting Review

Items queued here hit an architectural ambiguity or design choice that requires project owner input before implementation can proceed. Each item documents the exact state, relevant context, and the specific question.

---

## ✅ A-1 · How should `Real::PartialOrd` handle epsilon? (TODO H-1) — RESOLVED

**Decision (2026-06-22):** Option A — apply epsilon in `Real::PartialOrd`.

`Real::PartialEq` and `Real::PartialOrd` now use `CMP_EPSILON = 1e-13`. A separate `exact_eq` / `exact_cmp` helper is available for sort utilities and serialisation code that needs strict IEEE 754 ordering. The non-transitivity of epsilon equality is documented in an inline comment; `Real` is never used as a `HashMap` key.

---

## ✅ A-2 · Encoding flag design for `gm8emulator` (TODO M-2) — RESOLVED

**Decision (2026-06-22):** Default to `windows-1252`. CLI flag `-e`/`--encoding` added with supported values `windows-1252`, `shift-jis`, and `utf-8`.

---

## ✅ A-3 · `show_windowcol` in `gm_save.rs` (TODO M-7) — RESOLVED

**Decision (2026-06-22):** Field removed from `GMRoomSave`.

`show_windowcol` had no corresponding field in the game/room state and was never restored by `into_game()`. The field is not part of any GM8 save format that the engine currently supports. Removing it is a save-file compat break, but the GM manual explicitly recommends against persisting saves across sessions.

---
