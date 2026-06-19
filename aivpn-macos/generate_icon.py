#!/usr/bin/env python3
"""Generate AIVPN.icns from brand/icon-1024.png.

Works on both Linux and macOS (requires Pillow: pip install Pillow).
Output: /tmp/Aivpn.icns — build.sh picks it up automatically.
"""
import struct
import io
import os
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    sys.exit("Pillow is required: pip install Pillow")

SCRIPT_DIR = Path(__file__).parent
BRAND_ICON = SCRIPT_DIR.parent / "brand" / "icon-1024.png"
OUT = Path("/tmp/Aivpn.icns")

if not BRAND_ICON.exists():
    sys.exit(f"Brand icon not found: {BRAND_ICON}")

# ICNS OSType → pixel size pairs
ICONS = [
    (b'icp4', 16),
    (b'icp5', 32),
    (b'icp6', 64),
    (b'ic07', 128),
    (b'ic08', 256),
    (b'ic09', 512),
    (b'ic10', 1024),
]

img = Image.open(BRAND_ICON).convert("RGBA")
chunks = []
for ostype, size in ICONS:
    resized = img.resize((size, size), Image.LANCZOS)
    buf = io.BytesIO()
    resized.save(buf, format="PNG")
    png_data = buf.getvalue()
    chunks.append(ostype + struct.pack(">I", 8 + len(png_data)) + png_data)

body = b"".join(chunks)
total_size = 8 + len(body)
with open(OUT, "wb") as f:
    f.write(b"icns")
    f.write(struct.pack(">I", total_size))
    f.write(body)

print(f"Created {OUT} ({os.path.getsize(OUT):,} bytes)")
