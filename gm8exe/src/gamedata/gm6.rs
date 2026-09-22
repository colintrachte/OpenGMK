//! GameMaker 6.0 / 6.1 gamedata support.
//!
//! GM6.0 and GM6.1 use the *exact same* internal gamedata layout - "6.1" only changed where
//! in the compiled exe that data starts (extra OS-compatibility wrapper bytes), not the
//! format itself. See `legacy.rs` for the shared cipher/parsing code this builds on.

use super::legacy;
use crate::{reader::ReaderError, settings::GameHelpDialog, GameAssets, GameVersion};
use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;

/// Fixed offsets into the raw exe where GM6 gamedata may begin, depending on which
/// installer/OS-compatibility wrapper variant produced the executable.
const OFFSETS: [usize; 5] = [0, 700_000, 800_000, 1_420_000, 1_600_000];

/// Returns the offset gamedata begins at, if this looks like a GM6.0/6.1 executable.
pub fn detect(data: &[u8]) -> Option<usize> {
    OFFSETS.into_iter().find(|&offset| {
        data.get(offset..offset + 8)
            .map(|bytes| {
                let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
                let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                magic == 1234321 && version == 600
            })
            .unwrap_or(false)
    })
}

pub fn parse(data: &[u8], ico_file_raw: Option<Vec<u8>>, strict: bool) -> Result<GameAssets, ReaderError> {
    let offset = detect(data).ok_or(ReaderError::UnknownFormat)?;
    let mut reader = Cursor::new(&data[offset..]);

    let included_files = legacy::read_gm600_includes(&mut reader)?;

    let mut stream = legacy::decrypt_gm600(&mut reader)?;

    if stream.read_u32::<LE>()? != 1230600 {
        return Err(ReaderError::UnknownFormat)
    }
    let _unknown1 = stream.read_u32::<LE>()?;
    let _unknown2 = stream.read_u32::<LE>()?;
    let _pro = legacy::read_bool(&mut stream)?;
    let _unknown4 = stream.read_u32::<LE>()?;
    if stream.read_u32::<LE>()? != 1234321 || stream.read_u32::<LE>()? != 600 {
        return Err(ReaderError::UnknownFormat)
    }
    let _debug = legacy::read_bool(&mut stream)?;
    let game_id = stream.read_u32::<LE>()?;
    let mut guid = [0u32; 4];
    for g in guid.iter_mut() {
        *g = stream.read_u32::<LE>()?;
    }

    let (settings, constants) = legacy::read_settings(&mut stream)?;
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

    let help_dialog: GameHelpDialog = legacy::read_help(&mut stream)?;
    let library_init_strings = legacy::read_library_init_scripts(&mut stream)?;
    let room_order = legacy::read_room_order(&mut stream)?;

    Ok(GameAssets {
        triggers: Vec::new(),
        constants,
        extensions: Vec::new(),
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
