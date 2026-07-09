from PIL import Image, ImageDraw
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BG = (8, 14, 13, 255)
TEAL = (0, 229, 176, 255)
MAGENTA = (255, 61, 129, 255)


def shield_path(cx, cy, w, h):
    """Return point list for a simple shield silhouette centered at (cx, cy)."""
    top = cy - h / 2
    bottom = cy + h / 2
    left = cx - w / 2
    right = cx + w / 2
    mid_y = cy + h * 0.05
    return [
        (cx, top),
        (right, top + h * 0.12),
        (right, mid_y),
        (cx, bottom),
        (left, mid_y),
        (left, top + h * 0.12),
    ]


def make_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    pad = max(1, size // 16)
    d.rounded_rectangle([pad, pad, size - pad, size - pad], radius=max(2, size // 6), fill=BG)

    cx, cy = size / 2, size / 2 + size * 0.02
    w, h = size * 0.5, size * 0.62
    pts = shield_path(cx, cy, w, h)
    d.polygon(pts, outline=TEAL, width=max(1, size // 20))

    # crosshair / blocked-mark glyph inside the shield (magenta), signature
    # element distinguishing this from a purely defensive/passive shield
    r = size * 0.11
    lw = max(1, size // 18)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=MAGENTA, width=lw)
    diag = r * 0.75
    d.line([cx - diag, cy - diag, cx + diag, cy + diag], fill=MAGENTA, width=lw)

    return img


for s in [16, 32, 48, 128]:
    make_icon(s).save(ROOT / "icons" / f"icon{s}.png")

print("done")
