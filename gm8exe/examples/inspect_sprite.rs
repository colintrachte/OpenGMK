//! Inspect a sprite embedded in a GameMaker 8 executable without extracting or
//! modifying the game. Useful when checking whether a later GMX conversion
//! damaged a legacy source asset.

use std::{collections::BTreeMap, env, fs, process};

fn main() {
    let mut args = env::args().skip(1);
    let exe_path = args.next().unwrap_or_else(|| usage());
    let wanted = args.next().unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let mut bytes = fs::read(&exe_path).unwrap_or_else(|error| {
        eprintln!("failed to read {exe_path}: {error}");
        process::exit(1);
    });
    let assets = gm8exe::reader::from_exe(&mut bytes, None::<fn(&str)>, false, true).unwrap_or_else(|error| {
        eprintln!("failed to parse {exe_path}: {error}");
        process::exit(1);
    });

    let Some(sprite) = assets.sprites.iter().flatten().find(|sprite| sprite.name.to_string() == wanted) else {
        eprintln!("sprite {wanted:?} not found in {exe_path}");
        process::exit(2);
    };

    println!("sprite={} origin=({}, {}) frames={}", sprite.name, sprite.origin_x, sprite.origin_y, sprite.frames.len());
    for (index, frame) in sprite.frames.iter().enumerate() {
        let mut colours = BTreeMap::<[u8; 4], usize>::new();
        let mut opaque = 0usize;
        let mut bounds: Option<(u32, u32, u32, u32)> = None;
        for (pixel_index, pixel) in frame.data.chunks_exact(4).enumerate() {
            // Classic runner sprite chunks store colour channels in Windows
            // BGRA order; report conventional RGBA so the result can be
            // compared directly with a converted PNG.
            let rgba = [pixel[2], pixel[1], pixel[0], pixel[3]];
            *colours.entry(rgba).or_default() += 1;
            if rgba[3] != 0 {
                opaque += 1;
                let x = pixel_index as u32 % frame.width;
                let y = pixel_index as u32 / frame.width;
                bounds = Some(match bounds {
                    Some((left, top, right, bottom)) => (left.min(x), top.min(y), right.max(x), bottom.max(y)),
                    None => (x, y, x, y),
                });
            }
        }
        println!(
            "frame={index} size={}x{} bytes={} opaque={} bounds={bounds:?} colours={colours:?}",
            frame.width,
            frame.height,
            frame.data.len(),
            opaque
        );
    }
}

fn usage() -> ! {
    eprintln!("usage: inspect_sprite <game.exe> <sprite_name>");
    process::exit(64);
}
