//! Shared support for reading GameMaker 6.0/6.1/7.0 ("legacy") gamedata.
//!
//! GM6/GM7 use a materially different on-disk gamedata layout than GM8.0/8.1 (different
//! header, no antidec-style protection, a different "gmkrypt" swap-table cipher, and
//! different per-asset binary schemas). The detection offsets, cipher and per-asset field
//! layouts here were ported from the format research in
//! <https://github.com/elipsitz/gm_reader> (MIT/Apache-2.0), cross-checked against real
//! GameMaker 6 executables.
//!
//! Everything parsed here is normalized into the exact same [`crate::GameAssets`] shape
//! used for GM8.0/8.1, tagged as [`GameVersion::GameMaker8_0`], so the rest of the
//! toolchain (and `gm8decompiler`'s .gmk writer) doesn't need to know these formats exist.

use crate::{
    asset::{
        constant::Constant,
        extension::{CallingConvention, Extension, File, FileConst, FileFunction, FileKind, FunctionValueKind},
        included_file::ExportSetting,
        object::Object,
        path::Path,
        room::Room,
        sound::SoundFX,
        sprite::{CollisionMap, Frame},
        timeline::Timeline,
        Asset, Background, Error as AssetError, Font, IncludedFile, PascalString, Script, Sound, SoundKind, Sprite,
    },
    reader::ReaderError,
    settings::{GameHelpDialog, Settings},
    AssetList, GameVersion,
};
use byteorder::{ReadBytesExt, LE};
use flate2::bufread::ZlibDecoder;
use std::io::{self, Cursor, Read};

// ---------------------------------------------------------------------------------------
// Primitive stream helpers
// ---------------------------------------------------------------------------------------

pub(crate) fn read_bool(reader: &mut impl Read) -> io::Result<bool> {
    Ok(reader.read_i32::<LE>()? != 0)
}

const MAX_SAFE_ALLOC_SIZE: usize = 128 * 1024 * 1024; // 128 MB safety ceiling
const MAX_SAFE_STRING_SIZE: usize = 16 * 1024 * 1024; // 16 MB string ceiling
const MAX_SAFE_COLLECTION_ITEMS: usize = 1_000_000;

fn checked_count(value: u32, label: &str) -> io::Result<usize> {
    let count = value as usize;
    if count > MAX_SAFE_COLLECTION_ITEMS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} count exceeds safety limit: {count}"),
        ));
    }
    Ok(count)
}

pub(crate) fn read_pas_string_raw(reader: &mut impl Read) -> io::Result<PascalString> {
    let len = reader.read_u32::<LE>()? as usize;
    if len > MAX_SAFE_STRING_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("String length exceeds safety limit: {} bytes", len)));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(PascalString(buf.into_boxed_slice()))
}

pub(crate) fn read_blob(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = reader.read_u32::<LE>()? as usize;
    if len > MAX_SAFE_ALLOC_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Blob length exceeds safety limit: {} bytes", len)));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub(crate) fn skip_blob(reader: &mut impl Read) -> io::Result<()> {
    let len = reader.read_u32::<LE>()? as u64;
    if len > MAX_SAFE_ALLOC_SIZE as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Blob skip length exceeds safety limit: {} bytes", len)));
    }
    let copied = io::copy(&mut reader.take(len), &mut io::sink())?;
    if copied != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Blob ended after {copied} bytes; expected {len}"),
        ));
    }
    Ok(())
}

/// Reads a u32-prefixed zlib-compressed chunk and inflates it.
pub(crate) fn read_compressed(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    read_compressed_with_limit(reader, MAX_SAFE_ALLOC_SIZE)
}

fn read_compressed_with_limit(reader: &mut impl Read, output_limit: usize) -> io::Result<Vec<u8>> {
    let len = reader.read_u32::<LE>()? as usize;
    if len > MAX_SAFE_ALLOC_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Compressed chunk length exceeds safety limit: {} bytes", len)));
    }
    let mut compressed = vec![0u8; len];
    reader.read_exact(&mut compressed)?;
    let decoder = ZlibDecoder::new(compressed.as_slice());
    let mut limited = decoder.take(output_limit as u64 + 1);
    let mut out = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() > output_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Decompressed chunk exceeds safety limit: {output_limit} bytes"),
        ));
    }
    Ok(out)
}

/// Swaps the R and B channels of 4-byte-per-pixel pixeldata in-place (BGRA <-> RGBA).
pub(crate) fn bgra_to_rgba(data: &mut [u8]) {
    data.chunks_exact_mut(4).for_each(|c| c.swap(0, 2));
}

/// A reader over one asset-list entry, which is either borrowed straight from the parent
/// stream (pre-GM8 collections) or an owned, already-inflated buffer (GM8-style collections,
/// which wrap every entry in its own zlib chunk). Mirrors the "SectionWrapper" pattern GM's
/// own asset lists use once entries started being individually compressed.
enum ItemReader<'a, R> {
    Raw(&'a mut R),
    Compressed(Cursor<Vec<u8>>),
}

impl<'a, R: Read> Read for ItemReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ItemReader::Raw(r) => r.read(buf),
            ItemReader::Compressed(c) => c.read(buf),
        }
    }
}

fn item_reader<'a, R: Read>(reader: &'a mut R, compressed: bool) -> io::Result<ItemReader<'a, R>> {
    if compressed { Ok(ItemReader::Compressed(Cursor::new(read_compressed(reader)?))) } else { Ok(ItemReader::Raw(reader)) }
}

// ---------------------------------------------------------------------------------------
// "gmkrypt" cipher - a swap-table stream cipher used by GM5.3-7.0 gamedata, legacy scripts
// and GM7 extension file data.
// ---------------------------------------------------------------------------------------

pub(crate) fn make_generic_swap_table(a: u32, b: u32) -> [u8; 256] {
    let mut table0 = [0u8; 256];
    let mut table1 = [0u8; 256];
    for (i, slot) in table0.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for i in 1..10001u32 {
        let j = (1 + ((i.wrapping_mul(a).wrapping_add(b)) % 254)) as usize;
        table0.swap(j, j + 1);
    }
    for i in 1..256usize {
        table1[table0[i] as usize] = i as u8;
    }
    table1
}

pub(crate) fn make_gmkrypt_swap_table(seed: u32) -> [u8; 256] {
    let a = 6 + (seed % 250);
    let b = seed / 250;
    make_generic_swap_table(a, b)
}

pub(crate) fn do_swap(buffer: &mut [u8], table: &[u8; 256], use_offset: bool, initial_offset: usize) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        let t = *byte as usize;
        *byte = if use_offset { (table[t] as i64 - (initial_offset + i) as i64) as u8 } else { table[t] };
    }
}

/// Decrypts a "gmkrypt"-ciphered chunk.
pub(crate) fn gmkrypt_decrypt(
    mut input: Cursor<Vec<u8>>,
    initial_unencrypted: u64,
    has_garbage: bool,
    use_offset: bool,
) -> io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};

    let mut output = Vec::new();
    let start_pos = input.stream_position()?;

    io::copy(&mut Read::by_ref(&mut input).take(initial_unencrypted), &mut output)?;
    let swap_seed = if has_garbage {
        let s1 = input.read_u32::<LE>()?;
        let s2 = input.read_u32::<LE>()?;
        input.seek(SeekFrom::Current(i64::from(s1) * 4))?;
        let seed = input.read_u32::<LE>()?;
        input.seek(SeekFrom::Current(i64::from(s2) * 4))?;
        seed
    } else {
        input.read_u32::<LE>()?
    };
    io::copy(&mut Read::by_ref(&mut input).take(1), &mut output)?;
    let end_pos = input.stream_position()?;

    let swap_start = output.len();
    let swap_length = io::copy(&mut input, &mut output)? as usize;
    let swap_offset = (end_pos - start_pos) as usize;
    let swap_table = make_gmkrypt_swap_table(swap_seed);
    do_swap(&mut output[swap_start..(swap_start + swap_length)], &swap_table, use_offset, swap_offset);

    Ok(output)
}

pub(crate) fn decrypt_gm600(stream: &mut impl Read) -> io::Result<Cursor<Vec<u8>>> {
    let compressed = read_compressed(stream)?;
    Ok(Cursor::new(gmkrypt_decrypt(Cursor::new(compressed), 4, true, false)?))
}

pub(crate) fn decrypt_gm700(stream: &mut impl Read) -> io::Result<Cursor<Vec<u8>>> {
    let compressed = read_compressed(stream)?;
    Ok(Cursor::new(gmkrypt_decrypt(Cursor::new(compressed), 0, true, true)?))
}

// ---------------------------------------------------------------------------------------
// Pre-decryption include block (GM6 only - stores includes ahead of the main cipher)
// ---------------------------------------------------------------------------------------

pub(crate) fn read_gm600_includes(reader: &mut impl Read) -> Result<Vec<IncludedFile>, ReaderError> {
    let export_location = reader.read_u32::<LE>()?;
    let overwrite = read_bool(reader)?;
    let remove_at_end = read_bool(reader)?;
    let mut includes = Vec::new();
    loop {
        let name = read_pas_string_raw(reader)?;
        if name.0.as_ref() == b"READY" {
            break
        } else if name.0.as_ref() == b"D3DX8.dll" {
            skip_blob(reader)?;
        } else {
            let data = read_blob(reader)?;
            let export_settings = match export_location {
                0 => ExportSetting::NoExport,
                1 => ExportSetting::TempFolder,
                2 => ExportSetting::GameFolder,
                _ => ExportSetting::CustomFolder(PascalString(Box::new([]))),
            };
            includes.push(IncludedFile {
                source_path: PascalString(name.0.clone()),
                file_name: name,
                data_exists: true,
                source_length: data.len(),
                stored_in_gmk: true,
                embedded_data: Some(data.into_boxed_slice()),
                export_settings,
                overwrite_file: overwrite,
                free_memory: true,
                remove_at_end,
            });
        }
    }
    Ok(includes)
}

// ---------------------------------------------------------------------------------------
// Settings / help / misc trailers - shared across GM6.0/6.1/7.0
// ---------------------------------------------------------------------------------------

pub(crate) fn read_settings(reader: &mut impl Read) -> Result<(Settings, Vec<Constant>), ReaderError> {
    let version = reader.read_u32::<LE>()?;
    let mut item = item_reader(reader, version >= 800)?;

    let fullscreen = read_bool(&mut item)?;
    let interpolate_pixels = if version >= 600 { read_bool(&mut item)? } else { false };
    let dont_draw_border = read_bool(&mut item)?;
    let display_cursor = read_bool(&mut item)?;
    let (scaling, allow_resize, window_on_top, clear_colour) = if version >= 542 {
        (item.read_i32::<LE>()?, read_bool(&mut item)?, read_bool(&mut item)?, item.read_u32::<LE>()?)
    } else {
        (0, false, false, 0)
    };

    let set_resolution = read_bool(&mut item)?;
    let (colour_depth, resolution, frequency) = if version >= 542 {
        (item.read_u32::<LE>()?, item.read_u32::<LE>()?, item.read_u32::<LE>()?)
    } else {
        (0, 0, 0)
    };
    let dont_show_buttons = read_bool(&mut item)?;
    let vsync = if version >= 542 { read_bool(&mut item)? } else { false };
    let disable_screensaver = if version >= 800 { read_bool(&mut item)? } else { false };

    let f4_fullscreen_toggle = read_bool(&mut item)?;
    let f1_help_menu = read_bool(&mut item)?;
    let esc_close_game = read_bool(&mut item)?;
    let f5_save_f6_load = read_bool(&mut item)?;
    let (f9_screenshot, treat_close_as_esc) =
        if version >= 702 { (read_bool(&mut item)?, read_bool(&mut item)?) } else { (false, false) };
    let priority = item.read_u32::<LE>()?;
    let freeze_on_lose_focus = read_bool(&mut item)?;

    let loading_bar = item.read_u32::<LE>()?;
    let (backdata, frontdata) = if loading_bar > 0 {
        let back = if read_bool(&mut item)? { Some(read_compressed(&mut item)?.into_boxed_slice()) } else { None };
        let front = if read_bool(&mut item)? { Some(read_compressed(&mut item)?.into_boxed_slice()) } else { None };
        (back, front)
    } else {
        (None, None)
    };

    let custom_load_image =
        if read_bool(&mut item)? { Some(read_compressed(&mut item)?.into_boxed_slice()) } else { None };

    let transparent = read_bool(&mut item)?;
    let translucency = item.read_u32::<LE>()?;
    let scale_progress_bar = read_bool(&mut item)?;

    let show_error_messages = read_bool(&mut item)?;
    let log_errors = read_bool(&mut item)?;
    let always_abort = read_bool(&mut item)?;

    let (zero_uninitialized_vars, error_on_uninitialized_args, constants) = if version >= 800 {
        let flags = item.read_u32::<LE>()?;
        (flags & 0x1 != 0, flags & 0x2 != 0, Vec::new())
    } else {
        let zero_uninit = read_bool(&mut item)?;
        let constant_count = checked_count(item.read_u32::<LE>()?, "constant")?;
        let mut constants = Vec::with_capacity(constant_count);
        for _ in 0..constant_count {
            let name = read_pas_string_raw(&mut item)?;
            let expression = read_pas_string_raw(&mut item)?;
            constants.push(Constant { name, expression });
        }
        (zero_uninit, false, constants)
    };

    Ok((
        Settings {
            fullscreen,
            scaling,
            interpolate_pixels,
            clear_colour,
            allow_resize,
            window_on_top,
            dont_draw_border,
            dont_show_buttons,
            display_cursor,
            freeze_on_lose_focus,
            disable_screensaver,
            force_cpu_render: true,
            set_resolution,
            colour_depth,
            resolution,
            frequency,
            vsync,
            esc_close_game,
            treat_close_as_esc,
            f1_help_menu,
            f4_fullscreen_toggle,
            f5_save_f6_load,
            f9_screenshot,
            priority,
            custom_load_image,
            transparent,
            translucency,
            loading_bar,
            backdata,
            frontdata,
            scale_progress_bar,
            show_error_messages,
            log_errors,
            always_abort,
            zero_uninitialized_vars,
            error_on_uninitialized_args,
            swap_creation_events: false,
        },
        constants,
    ))
}

pub(super) fn read_help(reader: &mut impl Read) -> Result<GameHelpDialog, ReaderError> {
    let version = reader.read_u32::<LE>()?;
    if version < 600 {
        return Err(ReaderError::UnknownFormat)
    }
    let mut item = item_reader(reader, version >= 800)?;

    let bg_colour = item.read_u32::<LE>()?.into();
    let new_window = read_bool(&mut item)?;
    let caption = read_pas_string_raw(&mut item)?;
    let left = item.read_i32::<LE>()?;
    let top = item.read_i32::<LE>()?;
    let width = item.read_u32::<LE>()?;
    let height = item.read_u32::<LE>()?;
    let border = read_bool(&mut item)?;
    let resizable = read_bool(&mut item)?;
    let window_on_top = read_bool(&mut item)?;
    let freeze_game = read_bool(&mut item)?;
    let info = if version == 800 {
        read_pas_string_raw(&mut item)?
    } else {
        PascalString(read_compressed(&mut item)?.into_boxed_slice())
    };

    Ok(GameHelpDialog {
        bg_colour,
        new_window,
        caption,
        left,
        top,
        width,
        height,
        border,
        resizable,
        window_on_top,
        freeze_game,
        info,
    })
}

pub(super) fn read_library_init_scripts(reader: &mut impl Read) -> Result<Vec<PascalString>, ReaderError> {
    let version = reader.read_u32::<LE>()?;
    if version != 500 {
        return Err(ReaderError::UnknownFormat)
    }
    let count = checked_count(reader.read_u32::<LE>()?, "library initialization script")?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_pas_string_raw(reader)?);
    }
    Ok(out)
}

pub(super) fn read_room_order(reader: &mut impl Read) -> Result<Vec<i32>, ReaderError> {
    let version = reader.read_u32::<LE>()?;
    if version != 540 && version != 700 {
        return Err(ReaderError::UnknownFormat)
    }
    let count = checked_count(reader.read_u32::<LE>()?, "room order")?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(reader.read_i32::<LE>()?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Asset lists whose binary schema never changed across GM6/GM7/GM8.0 (430/500/541/530) -
// just delegate straight into gm8exe's own already-correct deserializers.
// ---------------------------------------------------------------------------------------

pub(super) fn read_asset_list<T: Asset>(reader: &mut impl Read, strict: bool) -> Result<AssetList<T>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "asset")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let asset = T::deserialize_exe(item, GameVersion::GameMaker8_0, strict)?;
        list.push(Some(Box::new(asset)));
    }
    Ok(list)
}

pub(super) fn read_objects(reader: &mut impl Read, strict: bool) -> Result<AssetList<Object>, ReaderError> {
    read_asset_list::<Object>(reader, strict)
}
pub(super) fn read_timelines(reader: &mut impl Read, strict: bool) -> Result<AssetList<Timeline>, ReaderError> {
    read_asset_list::<Timeline>(reader, strict)
}
pub(super) fn read_rooms(reader: &mut impl Read, strict: bool) -> Result<AssetList<Room>, ReaderError> {
    read_asset_list::<Room>(reader, strict)
}
pub(super) fn read_paths(reader: &mut impl Read, strict: bool) -> Result<AssetList<Path>, ReaderError> {
    read_asset_list::<Path>(reader, strict)
}

// ---------------------------------------------------------------------------------------
// Asset lists with their own pre-GM8 binary schema
// ---------------------------------------------------------------------------------------

pub(super) fn read_sounds(reader: &mut impl Read, strict: bool) -> Result<AssetList<Sound>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "sound")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let name = read_pas_string_raw(&mut item)?;
        let version = item.read_u32::<LE>()?;
        if strict && version != 600 && version != 800 {
            return Err(ReaderError::AssetError(AssetError::VersionError { expected: 600, got: version }))
        }
        let kind = SoundKind::from(item.read_u32::<LE>()?);
        let extension = read_pas_string_raw(&mut item)?;
        let source = read_pas_string_raw(&mut item)?;
        let data = if read_bool(&mut item)? { Some(read_blob(&mut item)?.into_boxed_slice()) } else { None };
        let effects = item.read_u32::<LE>()?;
        let fx = SoundFX {
            chorus: effects & 0b1 != 0,
            echo: effects & 0b10 != 0,
            flanger: effects & 0b100 != 0,
            gargle: effects & 0b1000 != 0,
            reverb: effects & 0b10000 != 0,
        };
        let volume = item.read_f64::<LE>()?;
        let pan = item.read_f64::<LE>()?;
        let preload = read_bool(&mut item)?;
        list.push(Some(Box::new(Sound { name, source, extension, data, kind, volume, pan, preload, fx })));
    }
    Ok(list)
}

pub(super) fn read_sprites(reader: &mut impl Read, strict: bool) -> Result<AssetList<Sprite>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "sprite")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let name = read_pas_string_raw(&mut item)?;
        let version = item.read_u32::<LE>()?;
        let sprite = match version {
            542 => {
                let mask_w = item.read_u32::<LE>()?;
                let mask_h = item.read_u32::<LE>()?;
                let mask_left = item.read_i32::<LE>()?;
                let mask_right = item.read_i32::<LE>()?;
                let mask_bottom = item.read_i32::<LE>()?;
                let mask_top = item.read_i32::<LE>()?;
                let _transparent = read_bool(&mut item)?;
                let _smooth_edges = read_bool(&mut item)?;
                let _preload = read_bool(&mut item)?;
                let _bb_type = item.read_u32::<LE>()?;
                let precise_collisions = read_bool(&mut item)?;
                let origin_x = item.read_i32::<LE>()?;
                let origin_y = item.read_i32::<LE>()?;

                let frame_count = checked_count(item.read_u32::<LE>()?, "sprite frame")?;
                let mut frames = Vec::with_capacity(frame_count);
                for _ in 0..frame_count {
                    let _ver = item.read_u32::<LE>()?;
                    let _present = item.read_u32::<LE>()?;
                    let width = item.read_u32::<LE>()?;
                    let height = item.read_u32::<LE>()?;
                    let mut data = read_compressed(&mut item)?;
                    bgra_to_rgba(&mut data);
                    frames.push(Frame { width, height, data: data.into_boxed_slice() });
                }

                let (colliders, per_frame_colliders) = if precise_collisions {
                    let colliders = frames
                        .iter()
                        .map(|frame| CollisionMap {
                            width: frame.width,
                            height: frame.height,
                            bbox_left: 0,
                            bbox_right: frame.width.saturating_sub(1),
                            bbox_top: 0,
                            bbox_bottom: frame.height.saturating_sub(1),
                            data: frame
                                .data
                                .chunks_exact(4)
                                .map(|p| p[3] == 255)
                                .collect::<Vec<_>>()
                                .into_boxed_slice(),
                        })
                        .collect();
                    (colliders, true)
                } else {
                    let mut data = Vec::with_capacity((mask_w * mask_h) as usize);
                    for y in 0..mask_h as i32 {
                        for x in 0..mask_w as i32 {
                            data.push(x >= mask_left && x <= mask_right && y >= mask_top && y <= mask_bottom);
                        }
                    }
                    (
                        vec![CollisionMap {
                            width: mask_w,
                            height: mask_h,
                            bbox_left: mask_left as u32,
                            bbox_right: mask_right as u32,
                            bbox_top: mask_top as u32,
                            bbox_bottom: mask_bottom as u32,
                            data: data.into_boxed_slice(),
                        }],
                        false,
                    )
                };

                Sprite { name, origin_x, origin_y, frames, colliders, per_frame_colliders }
            },
            800 | 810 => {
                let origin_x = item.read_i32::<LE>()?;
                let origin_y = item.read_i32::<LE>()?;
                let frame_count = checked_count(item.read_u32::<LE>()?, "sprite frame")?;
                let (frames, colliders, per_frame_colliders) = if frame_count != 0 {
                    let mut frames = Vec::with_capacity(frame_count);
                    for _ in 0..frame_count {
                        let _ver = item.read_u32::<LE>()?;
                        let width = item.read_u32::<LE>()?;
                        let height = item.read_u32::<LE>()?;
                        let data = read_blob(&mut item)?.into_boxed_slice();
                        frames.push(Frame { width, height, data });
                    }
                    if version == 810 {
                        item.read_u32::<LE>()?; // collision shape, unused
                    }
                    let per_frame_colliders = read_bool(&mut item)?;

                    fn read_collision(item: &mut impl Read) -> Result<CollisionMap, ReaderError> {
                        let _ver = item.read_u32::<LE>()?;
                        let width = item.read_u32::<LE>()?;
                        let height = item.read_u32::<LE>()?;
                        let bbox_left = item.read_u32::<LE>()?;
                        let bbox_right = item.read_u32::<LE>()?;
                        let bbox_bottom = item.read_u32::<LE>()?;
                        let bbox_top = item.read_u32::<LE>()?;
                        let pixel_count = width as usize * height as usize;
                        let mut data = Vec::with_capacity(pixel_count);
                        for _ in 0..pixel_count {
                            data.push(item.read_u32::<LE>()? != 0);
                        }
                        Ok(CollisionMap {
                            width,
                            height,
                            bbox_left,
                            bbox_right,
                            bbox_top,
                            bbox_bottom,
                            data: data.into_boxed_slice(),
                        })
                    }

                    let colliders = if per_frame_colliders {
                        (0..frame_count).map(|_| read_collision(&mut item)).collect::<Result<Vec<_>, _>>()?
                    } else {
                        vec![read_collision(&mut item)?]
                    };
                    (frames, colliders, per_frame_colliders)
                } else {
                    (Vec::new(), Vec::new(), false)
                };
                Sprite { name, origin_x, origin_y, frames, colliders, per_frame_colliders }
            },
            _ => {
                if strict {
                    return Err(ReaderError::AssetError(AssetError::VersionError { expected: 542, got: version }))
                }
                Sprite { name, origin_x: 0, origin_y: 0, frames: Vec::new(), colliders: Vec::new(), per_frame_colliders: false }
            },
        };
        list.push(Some(Box::new(sprite)));
    }
    Ok(list)
}

pub(super) fn read_backgrounds(reader: &mut impl Read, strict: bool) -> Result<AssetList<Background>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "background")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let name = read_pas_string_raw(&mut item)?;
        let version = item.read_u32::<LE>()?;
        let background = match version {
            543 => {
                let width = item.read_u32::<LE>()?;
                let height = item.read_u32::<LE>()?;
                let _transparent = read_bool(&mut item)?;
                let _smooth_edges = read_bool(&mut item)?;
                let _preload = read_bool(&mut item)?;
                let has_image = read_bool(&mut item)?;
                let data = if has_image {
                    let _ver = item.read_u32::<LE>()?;
                    let _present = item.read_u32::<LE>()?;
                    let _img_w = item.read_u32::<LE>()?;
                    let _img_h = item.read_u32::<LE>()?;
                    Some(read_compressed(&mut item)?.into_boxed_slice())
                } else {
                    None
                };
                Background { name, width, height, data }
            },
            710 => {
                let _ver2 = item.read_u32::<LE>()?;
                let width = item.read_u32::<LE>()?;
                let height = item.read_u32::<LE>()?;
                let data = if width > 0 && height > 0 { Some(read_blob(&mut item)?.into_boxed_slice()) } else { None };
                Background { name, width, height, data }
            },
            _ => {
                if strict {
                    return Err(ReaderError::AssetError(AssetError::VersionError { expected: 543, got: version }))
                }
                Background { name, width: 0, height: 0, data: None }
            },
        };
        list.push(Some(Box::new(background)));
    }
    Ok(list)
}

pub(super) fn read_scripts(reader: &mut impl Read, strict: bool) -> Result<AssetList<Script>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "script")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let name = read_pas_string_raw(&mut item)?;
        let version = item.read_u32::<LE>()?;
        let source = match version {
            400 => {
                let mut compressed = read_compressed(&mut item)?;
                let swap_table = make_gmkrypt_swap_table(12345);
                do_swap(&mut compressed, &swap_table, false, 0);
                read_pas_string_raw(&mut Cursor::new(compressed))?
            },
            800 => read_pas_string_raw(&mut item)?,
            _ => {
                if strict {
                    return Err(ReaderError::AssetError(AssetError::VersionError { expected: 800, got: version }))
                }
                PascalString(Box::new([]))
            },
        };
        list.push(Some(Box::new(Script { name, source })));
    }
    Ok(list)
}

pub(super) fn read_fonts(reader: &mut impl Read, strict: bool) -> Result<AssetList<Font>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "font")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        if !read_bool(&mut item)? {
            list.push(None);
            continue
        }
        let name = read_pas_string_raw(&mut item)?;
        let version = item.read_u32::<LE>()?;
        if version < 540 {
            if strict {
                return Err(ReaderError::AssetError(AssetError::VersionError { expected: 540, got: version }))
            }
            list.push(None);
            continue
        }
        let sys_name = read_pas_string_raw(&mut item)?;
        let size = item.read_u32::<LE>()?;
        let bold = read_bool(&mut item)?;
        let italic = read_bool(&mut item)?;
        let mut range_start = item.read_u32::<LE>()?;
        let range_end = item.read_u32::<LE>()?;
        let aa_level = (range_start & 0xFF000000) >> 24;
        let charset = (range_start & 0x00FF0000) >> 16;
        range_start &= 0x0000FFFF;

        let mut dmap = [0u32; 0x600];
        for val in dmap.iter_mut() {
            *val = item.read_u32::<LE>()?;
        }
        let map_width = item.read_u32::<LE>()?;
        let map_height = item.read_u32::<LE>()?;
        let pixel_map = if version == 540 {
            read_compressed(&mut item)?.into_boxed_slice()
        } else {
            read_blob(&mut item)?.into_boxed_slice()
        };

        list.push(Some(Box::new(Font {
            name,
            sys_name,
            size,
            bold,
            italic,
            range_start,
            range_end,
            charset,
            aa_level,
            dmap: Box::new(dmap),
            map_width,
            map_height,
            pixel_map,
        })));
    }
    Ok(list)
}

/// The "standard" (GM7/GM8-style) included-files list, as opposed to GM6's pre-decryption
/// name/blob loop (see [`read_gm600_includes`]).
pub(super) fn read_includes(reader: &mut impl Read, strict: bool) -> Result<Vec<IncludedFile>, ReaderError> {
    let collection_version = reader.read_u32::<LE>()?;
    let count = checked_count(reader.read_u32::<LE>()?, "included file")?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let mut item = item_reader(reader, collection_version >= 800)?;
        let version = item.read_u32::<LE>()?;
        if version != 620 && version != 800 {
            if strict {
                return Err(ReaderError::AssetError(AssetError::VersionError { expected: 800, got: version }))
            }
            continue
        }
        let file_name = read_pas_string_raw(&mut item)?;
        let source_path = read_pas_string_raw(&mut item)?;
        let data_exists = read_bool(&mut item)?;
        let source_length = item.read_u32::<LE>()? as usize;
        let stored_in_gmk = read_bool(&mut item)?;
        let embedded_data = if data_exists && stored_in_gmk {
            let bytes = if version == 620 { read_compressed(&mut item)? } else { read_blob(&mut item)? };
            Some(bytes.into_boxed_slice())
        } else {
            None
        };
        let export_flag = item.read_u32::<LE>()?;
        let custom_folder = read_pas_string_raw(&mut item)?;
        let export_settings = match export_flag {
            0 => ExportSetting::NoExport,
            1 => ExportSetting::TempFolder,
            2 => ExportSetting::GameFolder,
            _ => ExportSetting::CustomFolder(custom_folder),
        };
        let overwrite_file = read_bool(&mut item)?;
        let free_memory = read_bool(&mut item)?;
        let remove_at_end = read_bool(&mut item)?;
        list.push(IncludedFile {
            file_name,
            source_path,
            data_exists,
            source_length,
            stored_in_gmk,
            embedded_data,
            export_settings,
            overwrite_file,
            free_memory,
            remove_at_end,
        });
    }
    Ok(list)
}

// ---------------------------------------------------------------------------------------
// Extensions (GM7 only)
// ---------------------------------------------------------------------------------------

pub(super) fn read_extensions(reader: &mut impl Read, strict: bool) -> Result<Vec<Extension>, ReaderError> {
    let version = reader.read_u32::<LE>()?;
    if strict && version != 700 {
        return Err(ReaderError::AssetError(AssetError::VersionError { expected: 700, got: version }))
    }
    let count = checked_count(reader.read_u32::<LE>()?, "extension")?;
    let mut extensions = Vec::with_capacity(count);
    for _ in 0..count {
        let _ver = reader.read_u32::<LE>()?;
        let name = read_pas_string_raw(reader)?;
        let folder_name = read_pas_string_raw(reader)?;

        let file_count = checked_count(reader.read_u32::<LE>()?, "extension file")?;
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let _ver = reader.read_u32::<LE>()?;
            let name = read_pas_string_raw(reader)?;
            let kind = FileKind::from(reader.read_u32::<LE>()?);
            let initializer = read_pas_string_raw(reader)?;
            let finalizer = read_pas_string_raw(reader)?;
            let function_count = checked_count(reader.read_u32::<LE>()?, "extension function")?;
            let mut functions = Vec::with_capacity(function_count);
            for _ in 0..function_count {
                let _ver = reader.read_u32::<LE>()?;
                let name = read_pas_string_raw(reader)?;
                let external_name = read_pas_string_raw(reader)?;
                let convention = CallingConvention::from(reader.read_u32::<LE>()?);
                let id = reader.read_u32::<LE>()?;
                let arg_count = reader.read_i32::<LE>()?;
                let mut arg_types = [FunctionValueKind::GMReal; 17];
                for slot in arg_types.iter_mut() {
                    *slot = FunctionValueKind::from(reader.read_u32::<LE>()?);
                }
                let return_type = FunctionValueKind::from(reader.read_u32::<LE>()?);
                functions.push(FileFunction { name, external_name, convention, id, arg_count, arg_types, return_type });
            }

            let const_count = checked_count(reader.read_u32::<LE>()?, "extension constant")?;
            let mut consts = Vec::with_capacity(const_count);
            for _ in 0..const_count {
                let _ver = reader.read_u32::<LE>()?;
                let name = read_pas_string_raw(reader)?;
                let value = read_pas_string_raw(reader)?;
                consts.push(FileConst { name, value });
            }

            files.push(File { name, kind, initializer, finalizer, functions, consts, contents: Box::new([]) });
        }

        let raw_encrypted = read_blob(reader)?;
        if !raw_encrypted.is_empty() {
            let encrypted = Cursor::new(raw_encrypted);
            let mut decrypted = Cursor::new(gmkrypt_decrypt(encrypted, 0, false, false)?);
            for file in &mut files {
                if file.kind != FileKind::ActionLibrary {
                    file.contents = read_compressed(&mut decrypted)?.into_boxed_slice();
                }
            }
        }

        extensions.push(Extension { name, folder_name, files });
    }
    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use super::{checked_count, read_compressed_with_limit, skip_blob, MAX_SAFE_COLLECTION_ITEMS};
    use byteorder::{WriteBytesExt, LE};
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::{Cursor, Write};

    fn compressed_chunk(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut chunk = Vec::new();
        chunk.write_u32::<LE>(compressed.len() as u32).unwrap();
        chunk.extend_from_slice(&compressed);
        chunk
    }

    #[test]
    fn compressed_output_at_limit_is_accepted() {
        let mut chunk = Cursor::new(compressed_chunk(&[0x5A; 64]));
        assert_eq!(read_compressed_with_limit(&mut chunk, 64).unwrap(), vec![0x5A; 64]);
    }

    #[test]
    fn compressed_output_over_limit_is_rejected() {
        let mut chunk = Cursor::new(compressed_chunk(&[0x5A; 65]));
        let error = read_compressed_with_limit(&mut chunk, 64).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_skipped_blob_is_rejected() {
        let mut data = Vec::new();
        data.write_u32::<LE>(4).unwrap();
        data.extend_from_slice(&[1, 2]);
        let error = skip_blob(&mut Cursor::new(data)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn excessive_collection_count_is_rejected() {
        let error = checked_count((MAX_SAFE_COLLECTION_ITEMS + 1) as u32, "test").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
