//! GameMaker 5.0 / 5.3 gamedata support.
//!
//! GM5 executables bundle an encrypted GameMaker project (.gmd).
//! The payload begins with magic 1230500, followed by a 32-bit swap seed.
//! The stream is decrypted using the swap-table cipher.
//! The decrypted stream contains:
//!   - Registration author name (Pascal string)
//!   - Registration key (Pascal string)
//!   - Magic 1234321
//!   - Version 500 (GM5.0) or 530 (GM5.3)
//!   - The full .gmd project payload!
use super::legacy;
use crate::{
    reader::ReaderError,
    settings::{GameHelpDialog, Settings},
    GameAssets, GameVersion,
};
use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;

const CANDIDATE_OFFSETS: [usize; 6] = [
    1_250_000, // GM 5.0 (e.g. mage.exe)
    1_500_000, // GM 5.3 standard runner
    1_400_000,
    1_420_000,
    1_600_000,
    0,
];

fn check_at(data: &[u8], offset: usize) -> Option<(usize, u32, usize)> {
    if data.len() < offset + 8 {
        return None;
    }
    let magic = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    if magic != 1230500 {
        return None;
    }
    let swap_seed = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
    let test_len = 128.min(data.len() - (offset + 8));
    if test_len < 40 {
        return None;
    }
    let table = legacy::make_generic_swap_table(swap_seed, 0);
    let mut sample = data[offset + 8..offset + 8 + test_len].to_vec();
    for b in sample.iter_mut() {
        *b = table[*b as usize];
    }
    for i in 0..sample.len().saturating_sub(8) {
        let m = u32::from_le_bytes(sample[i..i + 4].try_into().unwrap());
        let v = u32::from_le_bytes(sample[i + 4..i + 8].try_into().unwrap());
        if m == 1234321 && (v == 500 || v == 530) {
            return Some((offset, swap_seed, i));
        }
    }
    None
}

pub fn detect(data: &[u8]) -> Option<(usize, u32, usize)> {
    for &offset in &CANDIDATE_OFFSETS {
        if let Some(info) = check_at(data, offset) {
            return Some(info);
        }
    }
    for (offset, window) in data.windows(4).enumerate() {
        let val = u32::from_le_bytes(window.try_into().unwrap());
        if val == 1230500 {
            if let Some(info) = check_at(data, offset) {
                return Some(info);
            }
        }
    }
    None
}

pub fn parse(
    data: &[u8],
    ico_file_raw: Option<Vec<u8>>,
    _strict: bool,
) -> Result<GameAssets, ReaderError> {
    let (offset, swap_seed, gmd_offset) = detect(data).ok_or(ReaderError::UnknownFormat)?;
    let table = legacy::make_generic_swap_table(swap_seed, 0);
    let mut decrypted = data[offset + 8..].to_vec();
    for b in decrypted.iter_mut() {
        *b = table[*b as usize];
    }
    let gmd_payload = decrypted[gmd_offset..].to_vec();
    let mut stream = Cursor::new(&gmd_payload);

    let _magic = stream.read_u32::<LE>()?;
    let version = stream.read_u32::<LE>()?;
    if version <= 530 {
        let _reserved = stream.read_u32::<LE>()?;
    }
    let game_id = stream.read_u32::<LE>()?;
    let mut guid = [0u32; 4];
    for g in guid.iter_mut() {
        *g = stream.read_u32::<LE>()?;
    }

    let default_settings = Settings {
        fullscreen: true,
        scaling: 0,
        interpolate_pixels: false,
        clear_colour: 0,
        allow_resize: false,
        window_on_top: false,
        dont_draw_border: false,
        dont_show_buttons: false,
        display_cursor: true,
        freeze_on_lose_focus: false,
        disable_screensaver: false,
        force_cpu_render: true,
        set_resolution: false,
        colour_depth: 0,
        resolution: 0,
        frequency: 0,
        vsync: false,
        esc_close_game: true,
        treat_close_as_esc: false,
        f1_help_menu: true,
        f4_fullscreen_toggle: true,
        f5_save_f6_load: true,
        f9_screenshot: false,
        priority: 0,
        custom_load_image: None,
        transparent: false,
        translucency: 0,
        loading_bar: 1,
        backdata: None,
        frontdata: None,
        scale_progress_bar: false,
        show_error_messages: true,
        log_errors: false,
        always_abort: false,
        zero_uninitialized_vars: false,
        error_on_uninitialized_args: false,
        swap_creation_events: false,
    };

    let (settings, constants) = legacy::read_settings(&mut stream)
        .unwrap_or_else(|_| (default_settings, Vec::new()));

    Ok(GameAssets {
        triggers: Vec::new(),
        constants,
        extensions: Vec::new(),
        sprites: Vec::new(),
        sounds: Vec::new(),
        backgrounds: Vec::new(),
        paths: Vec::new(),
        scripts: Vec::new(),
        fonts: Vec::new(),
        timelines: Vec::new(),
        objects: Vec::new(),
        rooms: Vec::new(),
        included_files: Vec::new(),
        version: GameVersion::GameMaker8_0,
        dx_dll: Vec::new(),
        ico_file_raw,
        help_dialog: GameHelpDialog {
            bg_colour: 0xFFFFFF.into(),
            new_window: false,
            caption: crate::asset::PascalString(Box::new([])),
            left: 0,
            top: 0,
            width: 600,
            height: 400,
            border: true,
            resizable: true,
            window_on_top: false,
            freeze_game: true,
            info: crate::asset::PascalString(Box::new([])),
        },
        last_instance_id: 100000,
        last_tile_id: 10000000,
        library_init_strings: Vec::new(),
        room_order: Vec::new(),
        settings,
        game_id,
        guid,
        raw_project: Some(gmd_payload),
    })
}
