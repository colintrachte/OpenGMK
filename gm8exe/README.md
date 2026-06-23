# gm8exe

Library for reading and writing GameMaker 8.x executables into Rust data structures.

## Architecture

A GM8 executable is a standard Windows PE file with the game engine (runner) as its code,
plus a **gamedata** section appended at the end of the file. The gamedata section contains all
project assets: sprites, sounds, backgrounds, paths, scripts, fonts, timelines, objects, rooms,
and settings. When the game runs, the runner reads this appended section from itself on disk.

### Reader

The main entry point is [`reader::from_exe`], which accepts a byte slice of the full `.exe` and
returns a [`GameAssets`] structure containing every asset decoded into typed Rust structs.

Internally the reader:
1. Detects and unpacks **UPX-compressed** executables automatically.
2. Locates the gamedata section by scanning for the GM magic byte pattern.
3. Identifies the **GM version** (8.0 vs 8.1) from the format header.
4. Decompresses each zlib-compressed asset chunk and deserialises it.
5. Optionally parallelises asset loading across CPU cores via `rayon` when `multithread = true`.

The format is partially documented in the source and in the comments of
`gamedata/gm80.rs` and `gamedata/gm81.rs`.

### Writer / Serialiser

Each asset type implements the [`asset::Asset`] trait, which provides `serialize_exe` to write
the asset back to the GM8 wire format. The decompiler uses this to reconstruct `.gmk` / `.gm81`
project files from loaded assets.

### Error handling

`reader::from_exe` returns `Result<GameAssets, ReaderError>`. Asset-level errors are wrapped in
`ReaderError::AssetError`. In strict mode (`strict = true`) version mismatches and other
recoverable inconsistencies are promoted to errors; in lenient mode they are silently ignored.

## Usage

```rust
let exe_bytes: Vec<u8> = std::fs::read("game.exe")?;
let assets = gm8exe::reader::from_exe(
    &mut exe_bytes,
    Some(|msg: &str| eprintln!("{}", msg)), // optional logger
    false, // strict
    true,  // multithread
)?;
// assets.sprites, assets.rooms, assets.objects, ...
```

## Documentation

Build local docs with:

```sh
cargo doc --open
```

The best entry point for understanding the full API is `reader::from_exe` and the `GameAssets` struct.
