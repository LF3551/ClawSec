#!/usr/bin/env python3
"""Generate docs/assets/social-preview.png (1280x640) for ClawSec.

Used as the GitHub social preview (Settings -> General -> Social preview) and
as the README header. Vector-drawn, so it stays sharp; rendered at 2x and
downsampled for anti-aliasing.  Requires Pillow:  python3 docs/assets/make-social-preview.py
"""
import math
import os

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

W, H, S = 1280, 640, 2                     # output size, supersampling factor
MINT = (46, 230, 168)
MINT_DIM = (46, 230, 168, 70)
WHITE = (240, 246, 252)
GREY = (148, 163, 184)
BG_TOP, BG_BOTTOM = (8, 13, 24), (15, 27, 45)
FONTS = "/usr/share/fonts/truetype/liberation"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "social-preview.png")


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTS, name), size * S)


def bezier(p0, p1, p2, n=40):
    return [((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
             (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1])
            for t in (i / n for i in range(n + 1))]


def shield_points(cx, cy, w, h):
    """Classic shield: flat-ish top with a dip, straight sides, pointed bottom."""
    top = cy - h / 2
    pts = []
    pts += bezier((cx - w / 2, top + h * 0.10), (cx - w * 0.22, top + h * 0.06), (cx, top))
    pts += bezier((cx, top), (cx + w * 0.22, top + h * 0.06), (cx + w / 2, top + h * 0.10))[1:]
    pts += bezier((cx + w / 2, top + h * 0.10), (cx + w * 0.52, top + h * 0.62), (cx, top + h))[1:]
    pts += bezier((cx, top + h), (cx - w * 0.52, top + h * 0.62), (cx - w / 2, top + h * 0.10))[1:]
    return pts


def claw(draw, p0, p1, p2, width, fill=MINT):
    """A tapered, slightly curved slash."""
    pts = bezier(p0, p1, p2, 60)
    left, right = [], []
    for i, (x, y) in enumerate(pts):
        t = i / (len(pts) - 1)
        w = width * math.sin(math.pi * t) ** 0.8 + 0.5 * S
        j = min(i + 1, len(pts) - 1)
        k = max(i - 1, 0)
        dx, dy = pts[j][0] - pts[k][0], pts[j][1] - pts[k][1]
        n = math.hypot(dx, dy) or 1
        nx, ny = -dy / n, dx / n
        left.append((x + nx * w / 2, y + ny * w / 2))
        right.append((x - nx * w / 2, y - ny * w / 2))
    draw.polygon(left + right[::-1], fill=fill)


def smooth(mask, radius):
    """Round corners of a binary mask: blur, then threshold."""
    return mask.filter(ImageFilter.GaussianBlur(radius)).point(lambda v: 255 if v > 127 else 0)


def erode(mask, px):
    """Shrink a binary mask by px pixels everywhere (uniform border width)."""
    out = mask
    step = 9                                    # MinFilter in odd steps keeps it fast
    while px > 0:
        k = min(step, 2 * px + 1)
        k += (k + 1) % 2                        # odd kernel
        out = out.filter(ImageFilter.MinFilter(k))
        px -= (k - 1) // 2
    return smooth(out, 2 * S)


def text_fit(draw, text, fontname, size, max_w):
    while size > 10:
        f = font(fontname, size)
        if draw.textlength(text, font=f) <= max_w * S:
            return f
        size -= 1
    return font(fontname, size)


def main():
    img = Image.new("RGB", (W * S, H * S))
    px = img.load()
    for y in range(H * S):                      # vertical gradient
        t = y / (H * S - 1)
        c = tuple(int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3))
        for x in range(W * S):
            px[x, y] = c

    # faint grid
    grid = Image.new("RGBA", img.size, (0, 0, 0, 0))
    g = ImageDraw.Draw(grid)
    for x in range(0, W * S, 40 * S):
        g.line([(x, 0), (x, H * S)], fill=(255, 255, 255, 10), width=S)
    for y in range(0, H * S, 40 * S):
        g.line([(0, y), (W * S, y)], fill=(255, 255, 255, 10), width=S)
    img.paste(grid, (0, 0), grid)

    # glow behind the shield
    cx, cy = 290 * S, 318 * S
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse([cx - 230 * S, cy - 230 * S, cx + 230 * S, cy + 230 * S],
                                 fill=(46, 230, 168, 55))
    glow = glow.filter(ImageFilter.GaussianBlur(90 * S))
    img.paste(glow, (0, 0), glow)

    d = ImageDraw.Draw(img, "RGBA")

    # shield + claw marks
    # Shield: a mask with slightly rounded corners; the border is the mask
    # minus its uniformly eroded interior, so it has the same width
    # everywhere (also at the corners and the bottom point).
    sw, sh, border = 300 * S, 360 * S, 15 * S
    outer = Image.new("L", img.size, 0)
    ImageDraw.Draw(outer).polygon(shield_points(cx, cy, sw, sh), fill=255)
    outer = smooth(outer, 4 * S)
    inner = erode(outer, border)
    ring = ImageChops.subtract(outer, inner)
    img.paste(Image.new("RGB", img.size, (12, 22, 38)), (0, 0), inner)
    img.paste(Image.new("RGB", img.size, MINT), (0, 0), ring)

    # Claw marks, clipped to the interior with a gap so they never touch
    # the border.
    claws = Image.new("L", img.size, 0)
    cd = ImageDraw.Draw(claws)
    # Diagonal slashes run down to the left, so the group sits slightly right
    # of centre; chosen so that no claw pixel touches the border gap.
    ccy = cy - 24 * S
    for off, length in ((-44, 0.70), (0, 0.86), (44, 0.70)):
        o = (off + 20) * S
        top = (cx + o + 50 * S * length, ccy - 110 * S * length)
        bottom = (cx + o - 50 * S * length, ccy + 96 * S * length)
        ctrl = (cx + o + 16 * S, ccy - 2 * S)    # bow the slash outwards
        claw(cd, top, ctrl, bottom, 22 * S, fill=255)
    claws = ImageChops.multiply(claws, erode(inner, 16 * S))
    img.paste(Image.new("RGB", img.size, MINT), (0, 0), claws)
    d = ImageDraw.Draw(img, "RGBA")

    # text block
    x0, max_w = 520, 700
    d.text((x0 * S, 118 * S), "ClawSec", font=font("LiberationSans-Bold.ttf", 112), fill=WHITE)
    d.text((x0 * S, 262 * S), "Encrypted netcat with forward secrecy",
           font=text_fit(d, "Encrypted netcat with forward secrecy", "LiberationSans-Bold.ttf", 40, max_w),
           fill=MINT)
    d.text((x0 * S, 322 * S), "Tunnels · File transfer · SOCKS5 · Port forwarding · VPN",
           font=text_fit(d, "Tunnels · File transfer · SOCKS5 · Port forwarding · VPN",
                         "LiberationSans-Regular.ttf", 30, max_w),
           fill=WHITE)

    # crypto chips
    chip_font = font("LiberationMono-Bold.ttf", 24)
    x = x0 * S
    y = 392 * S
    for label in ("AES-256-GCM", "X25519", "Argon2id", "ML-KEM-768"):
        tw = d.textlength(label, font=chip_font)
        pad = 16 * S
        d.rounded_rectangle([x, y, x + tw + 2 * pad, y + 46 * S], radius=23 * S,
                            fill=(46, 230, 168, 28), outline=MINT, width=2 * S)
        d.text((x + pad, y + 9 * S), label, font=chip_font, fill=MINT)
        x += tw + 2 * pad + 14 * S

    # terminal line
    term_font = font("LiberationMono-Regular.ttf", 22)
    ty = 480 * S
    d.rounded_rectangle([x0 * S, ty, (x0 + max_w) * S, ty + 54 * S], radius=10 * S,
                        fill=(0, 0, 0, 120), outline=(255, 255, 255, 30), width=S)
    d.text(((x0 + 18) * S, ty + 15 * S), "$", font=term_font, fill=MINT)
    cmd = "clawsec --key-file key --send data.tgz host 4444"
    d.text(((x0 + 44) * S, ty + 15 * S), cmd,
           font=text_fit(d, cmd, "LiberationMono-Regular.ttf", 22, max_w - 64), fill=WHITE)

    # footer
    d.text((x0 * S, 572 * S), "github.com/LF3551/ClawSec   ·   brew install lf3551/clawsec/clawsec",
           font=text_fit(d, "github.com/LF3551/ClawSec   ·   brew install lf3551/clawsec/clawsec",
                         "LiberationSans-Regular.ttf", 22, max_w),
           fill=GREY)

    img.resize((W, H), Image.LANCZOS).save(OUT, optimize=True)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
