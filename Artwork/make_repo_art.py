#!/usr/bin/env python3
# Repo art from AppIcon-1024.png: <out>/icons/NonceSetX.png (rounded 1024) and <out>/depiction/noncesetx/banner.png (1920x1080).
# python3 make_repo_art.py ~/Documents/apt
import os, sys
from PIL import Image, ImageDraw, ImageFont

here = os.path.dirname(os.path.abspath(__file__))
out = os.path.expanduser(sys.argv[1])
src = Image.open(os.path.join(here, "AppIcon-1024.png")).convert("RGBA")

def rounded(img, size):
    img = img.resize((size, size), Image.LANCZOS)
    big = size * 4
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=int(big * 0.2237), fill=255)
    img.putalpha(mask.resize((size, size), Image.LANCZOS))
    return img

os.makedirs(os.path.join(out, "depiction", "noncesetx"), exist_ok=True)
os.makedirs(os.path.join(out, "icons"), exist_ok=True)
rounded(src, 1024).save(os.path.join(out, "icons", "NonceSetX.png"))

# Banner: the icon's own gradient (light blue top-left -> deep blue bottom-right), icon left, name right
W, H = 1920, 1080
top, bottom = (99, 188, 253), (14, 98, 253)
grad = Image.new("RGB", (W, H))
px = grad.load()
for y in range(H):
    for x in range(W):
        t = (x / W + y / H) / 2
        px[x, y] = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
banner = grad.convert("RGBA")

icon = rounded(src, 420)
shadow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
ImageDraw.Draw(shadow).rounded_rectangle((300, 345, 300 + 420, 345 + 420), radius=94, fill=(0, 40, 120, 90))
from PIL import ImageFilter
banner = Image.alpha_composite(banner, shadow.filter(ImageFilter.GaussianBlur(30)))
banner.alpha_composite(icon, (290, 320))

d = ImageDraw.Draw(banner)
title = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 150)
sub = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 52)
try:
    title.set_variation_by_name("Bold")
    sub.set_variation_by_name("Medium")
except Exception:
    pass
d.text((800, 400), "NonceSetX", font=title, fill="white")
d.text((806, 600), "APNonce · SHSH · Generator", font=sub, fill=(255, 255, 255, 225))
d.text((806, 672), "Dopamine  iOS 15 – 18, 26", font=sub, fill=(255, 255, 255, 190))
banner.convert("RGB").save(os.path.join(out, "depiction", "noncesetx", "banner.png"))
