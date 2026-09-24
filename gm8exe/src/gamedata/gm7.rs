//! GameMaker 7.0 gamedata support. See `legacy.rs` for the shared cipher/parsing code.

use super::legacy;
use crate::{reader::ReaderError, GameAssets, GameVersion};
use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;

/// The fixed offset into the raw exe where GM7.0 gamedata begins.
const OFFSET: usize = 1_980_000;

/// Returns the offset gamedata begins at, if this looks like a GM7.0 executable.
pub fn detect(data: &[u8]) -> Option<usize> {
    let bytes = data.get(OFFSET..OFFSET + 8)?;
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if magic == 1234321 && version == 700 { Some(OFFSET) } else { None }
}

pub fn parse(data: &[u8], ico_file_raw: Option<Vec<u8>>, strict: bool) -> Result<GameAssets, ReaderError> {
    let offset = detect(data).ok_or(ReaderError::UnknownFormat)?;
    let mut reader = Cursor::new(&data[offset..]);
    let _magic = reader.read_u32::<LE>()?;
    let _version = reader.read_u32::<LE>()?;
    let _debug = legacy::read_bool(&mut reader)?;
    let (settings, constants) = legacy::read_settings(&mut reader)?;

    // Embedded D3DX8.dll (name, then content) - unused by the .gmk writer, so just skip it.
    legacy::skip_blob(&mut reader)?;
    legacy::skip_blob(&mut reader)?;

    let mut stream = legacy::decrypt_gm700(&mut reader)?;

    let _pro = legacy::read_bool(&mut stream)?;
    let game_id = stream.read_u32::<LE>()?;
    let mut guid = [0u32; 4];
    for g in guid.iter_mut() {
        *g = stream.read_u32::<LE>()?;
    }

    let extensions = legacy::read_extensions(&mut stream, strict)?;
    let sounds = legacy::read_sounds(&mut stream, strict)?;
    let sprites = legacy::read_sprites(&mut stream, strict)?;
    let backgrounds = legacy::read_backgrounds(&mut stream, strict)?;
    let paths = legacy::read_paths(&mut stream, strict)?;
    let scripts = legacy::read_scripts(&mut stream, strict)?;
    let fonts = legacy::read_fonts(&mut stream, strict)?;
    let timelines = legacy::read_timelines(&mut stream, strict)?;
    let objects = legacy::read_objects(&mut stream, strict)?;
    let rooms = legacy::read_rooms(&mut stream, strict)?;

    let last_instance_id = stream.read_i32::<LE>()?;
    let last_tile_id = stream.read_i32::<LE>()?;

    let included_files = legacy::read_includes(&mut stream, strict)?;
    let help_dialog = legacy::read_help(&mut stream)?;
    let library_init_strings = legacy::read_library_init_scripts(&mut stream)?;
    let room_order = legacy::read_room_order(&mut stream)?;

    Ok(GameAssets {
        triggers: Vec::new(),
        constants,
        extensions,
        sprites,
        sounds,
        backgrounds,
        paths,
        scripts,
        fonts,
        timelines,
        objects,
        rooms,
        included_files,
        version: GameVersion::GameMaker8_0,
        dx_dll: Vec::new(),
        ico_file_raw,
        help_dialog,
        last_instance_id,
        last_tile_id,
        library_init_strings,
        room_order,
        settings,
        game_id,
        guid,
        raw_project: None,
    })
}
