#!/usr/bin/env bash
# Generate Retina / multi-size wallpaper pack from masters.
# Requires ImageMagick (`magick`).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DAY="$ROOT/masters/mgw-day-16x9.jpg"
NIGHT="$ROOT/masters/mgw-night-16x9.jpg"
PHONE="$ROOT/masters/mgw-phone-9x16.jpg"
TAB="$ROOT/masters/mgw-tablet-3x4.jpg"

export_size() {
  local src="$1" w="$2" h="$3" dest="$4"
  mkdir -p "$(dirname "$dest")"
  magick "$src" -filter Lanczos -resize "${w}x${h}^" -gravity center -extent "${w}x${h}" \
    -quality 92 -strip "$dest"
  echo "  $(basename "$dest") ($(magick identify -format '%wx%h' "$dest"))"
}

echo "== desktop day =="
export_size "$DAY" 1920 1080 "$ROOT/desktop/mgw-day-1920x1080.png"
export_size "$DAY" 2560 1440 "$ROOT/desktop/mgw-day-2560x1440.png"
export_size "$DAY" 2560 1600 "$ROOT/desktop/mgw-day-2560x1600.png"
export_size "$DAY" 2880 1800 "$ROOT/desktop/@2x/mgw-day-2880x1800.png"
export_size "$DAY" 3024 1964 "$ROOT/desktop/@2x/mgw-day-3024x1964.png"
export_size "$DAY" 3456 2234 "$ROOT/desktop/@2x/mgw-day-3456x2234.png"
export_size "$DAY" 3840 2160 "$ROOT/desktop/@2x/mgw-day-3840x2160.png"
export_size "$DAY" 5120 2880 "$ROOT/desktop/@2x/mgw-day-5120x2880.png"
export_size "$DAY" 7680 4320 "$ROOT/desktop/@3x/mgw-day-7680x4320.png"

echo "== desktop night =="
export_size "$NIGHT" 1920 1080 "$ROOT/desktop/mgw-night-1920x1080.png"
export_size "$NIGHT" 3840 2160 "$ROOT/desktop/@2x/mgw-night-3840x2160.png"
export_size "$NIGHT" 5120 2880 "$ROOT/desktop/@2x/mgw-night-5120x2880.png"

echo "== mobile =="
export_size "$PHONE" 1080 1920 "$ROOT/mobile/mgw-phone-1080x1920.png"
export_size "$PHONE" 1440 2560 "$ROOT/mobile/@2x/mgw-phone-1440x2560.png"
export_size "$PHONE" 1170 2532 "$ROOT/mobile/@3x/mgw-phone-1170x2532.png"
export_size "$PHONE" 1284 2778 "$ROOT/mobile/@3x/mgw-phone-1284x2778.png"
export_size "$PHONE" 1290 2796 "$ROOT/mobile/@3x/mgw-phone-1290x2796.png"

echo "== tablet =="
export_size "$TAB" 1536 2048 "$ROOT/tablet/mgw-ipad-1536x2048.png"
export_size "$TAB" 1668 2388 "$ROOT/tablet/@2x/mgw-ipad-1668x2388.png"
export_size "$TAB" 2048 2732 "$ROOT/tablet/@2x/mgw-ipad-2048x2732.png"

if [[ -f "$ROOT/svg/mgw-wall.svg" ]]; then
  echo "== svg retina =="
  magick "$ROOT/svg/mgw-wall.svg" -resize 3840x2160 "$ROOT/desktop/@2x/mgw-svg-3840x2160.png"
  magick "$ROOT/svg/mgw-wall.svg" -resize 5120x2880 "$ROOT/desktop/@2x/mgw-svg-5120x2880.png"
fi

ZIP="$ROOT/mgw-wallpaper-pack.zip"
rm -f "$ZIP"
(
  cd "$(dirname "$ROOT")"
  zip -r "$ZIP" wallpapers \
    -x 'wallpapers/mgw-wallpaper-pack.zip' \
    -x 'wallpapers/**/.DS_Store'
)
echo "pack: $ZIP ($(du -h "$ZIP" | awk '{print $1}'))"
