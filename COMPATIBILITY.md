# OpenGMK Game Compatibility

This document tracks games known to work, partially work, or fail under OpenGMK.
Status is reported against the current `master` branch unless otherwise noted.

**Status key:**
- ✅ Working — playable, no major issues
- ⚠️ Partial — playable with some graphical, audio, or behaviour quirks
- ❌ Broken — crashes or fails to load
- 🔬 Untested — not yet verified

Community reports are welcome. Open an issue on GitHub with the game name,
GM8 version used to create it, and a description of any problems.

---

## Known Working

| Game | GM Version | Notes |
|---|---|---|
| (no entries yet — submit yours via a GitHub issue) | | |

---

## Known Partial

| Game | GM Version | Issue | Workaround |
|---|---|---|---|
| Undertale Demo | GM 8.x | Runtime errors on some code paths (issue #116) | None currently |
| Crimelife 3 | GM 8.x | Unimplemented kernel function errors (issue #136) | Now returns stub defaults; may progress further |
| New Super Mario Forever 2012 | GM 8.x | Graphical issues; TAS mode freeze (issue #161) | None currently |

---

## Known Broken

| Game | GM Version | Reason |
|---|---|---|
| GameMaker: Studio games | Studio | OpenGMK only supports GameMaker Classic (pre-Studio) executables |

---

## Notes

- **GameMaker version**: GM8 refers to GameMaker 8.0 and 8.1. Games compiled with GameMaker: Studio are not supported.
- **OpenGL requirement**: OpenGMK requires OpenGL 3.3 with GLSL 3.30. Games will fail to launch on very old Intel integrated graphics.
- **Text encoding**: Most Western GM8 games use Windows-1252 (the default). Japanese games need `--encoding shift-jis`.
- **32-bit DLLs (Windows 64-bit)**: Games using DLL extensions like GMFMODSimple require the WoW64 server binary. See `README.org` for build instructions.
