#!/usr/bin/env python3
# Resources/LaunchIcon@2x/@3x.png (120 pt) from AppIcon-1024.png with the home screen corner radius.
import os
from PIL import Image, ImageDraw

here = os.path.dirname(os.path.abspath(__file__))
src = Image.open(os.path.join(here, "AppIcon-1024.png")).convert("RGBA")
for scale in (2, 3):
    size = 120 * scale
    icon = src.resize((size, size), Image.LANCZOS)
    # Supersampled mask for smooth edges
    big = size * 4
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=int(big * 0.2237), fill=255)
    icon.putalpha(mask.resize((size, size), Image.LANCZOS))
    icon.save(os.path.join(here, "..", "Resources", f"LaunchIcon@{scale}x.png"))
