"""
Generates valid cyber shield PNG icons for the Chrome extension in sizes 16, 32, 48, and 128.
Pure Python using standard library zlib and struct.
"""
import os
import struct
import zlib
from pathlib import Path


def create_shield_png(size: int) -> bytes:
    width = size
    height = size
    raw_data = bytearray()

    for y in range(height):
        raw_data.append(0)  # filter type 0
        for x in range(width):
            nx = (x - (width / 2.0)) / (width / 2.0)
            ny = (y - (height / 2.0)) / (height / 2.0)

            # Shield shape formula
            in_shield = False
            if ny < 0.2:
                in_shield = abs(nx) < 0.82 and ny > -0.85
            else:
                in_shield = abs(nx) < (0.82 - (ny - 0.2) * 0.95) and ny < 0.9

            if in_shield:
                edge = (abs(nx) > 0.65) or (ny < -0.7) or (ny > 0.7)
                if edge:
                    raw_data.extend([6, 182, 212, 255])  # Cyan border
                else:
                    dist = (nx * nx + ny * ny) ** 0.5
                    glow = max(0, int(255 * (1.0 - dist)))
                    raw_data.extend([12, min(255, 30 + glow // 2), min(255, 60 + glow), 255])
            else:
                raw_data.extend([0, 0, 0, 0])

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw_data), level=9))
    png += chunk(b"IEND", b"")
    return png


def main():
    icons_dir = Path(__file__).resolve().parent / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)

    sizes = [16, 32, 48, 128]
    for s in sizes:
        icon_path = icons_dir / f"icon-{s}.png"
        png_bytes = create_shield_png(s)
        icon_path.write_bytes(png_bytes)
        print(f"Generated {icon_path.name} ({len(png_bytes)} bytes)")


if __name__ == "__main__":
    main()
