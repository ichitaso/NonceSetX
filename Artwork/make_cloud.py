# NonceSetX icon: a clean white cloud on a soft blue gradient (successor of NonceSet143's OTA cloud)
import sys
from PIL import Image, ImageDraw, ImageFilter, ImageChops

W = 2048
OUT, SPARKLE = sys.argv[1], (len(sys.argv) > 2 and sys.argv[2] == "sparkle")

def vgrad(c1, c2):
    g = Image.new("RGB", (1, 256))
    for y in range(256):
        t = y / 255
        g.putpixel((0, y), tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)))
    return g.resize((W, W), Image.BICUBIC)

def circle(d, cx, cy, r, fill=255):
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)

# Background: soft blue gradient with a gentle light in the upper middle
bg = vgrad((118, 190, 255), (36, 104, 226))
glow = Image.new("L", (W, W), 0)
circle(ImageDraw.Draw(glow), W * 0.5, W * 0.36, W * 0.42)
glow = glow.filter(ImageFilter.GaussianBlur(W * 0.16)).point(lambda v: int(v * 0.28))
bg = Image.composite(Image.new("RGB", (W, W), (190, 228, 255)), bg, glow)

# Cloud: base pill + three lobes, flat bottom
m = Image.new("L", (W, W), 0)
d = ImageDraw.Draw(m)
bottom = W * 0.655
h = W * 0.225
d.rounded_rectangle([W * 0.185, bottom - h, W * 0.815, bottom], radius=h / 2, fill=255)
circle(d, W * 0.355, bottom - h * 0.98, W * 0.118)   # left lobe
circle(d, W * 0.560, bottom - h * 1.20, W * 0.180)   # big lobe
cut = Image.new("L", (W, W), 0)
ImageDraw.Draw(cut).rectangle([0, bottom, W, W], fill=255)
m = ImageChops.subtract(m, cut).filter(ImageFilter.GaussianBlur(1.2))

# Sparkles (upper right, kept clear of the cloud edge)
sp = Image.new("L", (W, W), 0)
if SPARKLE:
    sd = ImageDraw.Draw(sp)
    def star(cx, cy, r, t):
        sd.polygon([(cx, cy - r), (cx + t, cy - t), (cx + r, cy), (cx + t, cy + t), (cx, cy + r), (cx - t, cy + t), (cx - r, cy), (cx - t, cy - t)], fill=255)
    star(W * 0.835, W * 0.275, W * 0.066, W * 0.016)
    star(W * 0.905, W * 0.385, W * 0.028, W * 0.0075)
    sp = sp.filter(ImageFilter.GaussianBlur(1.2))

# Place the cloud body: a touch left to balance the sparkles, vertically centred
bx0, by0, bx1, by1 = m.getbbox()
dx = int(round(W * (0.47 if SPARKLE else 0.50) - (bx0 + bx1) / 2))
dy = int(round(W * 0.505 - (by0 + by1) / 2))
m = ImageChops.offset(m, dx, dy)
sp = ImageChops.offset(sp, dx, dy)

# Soft shadow
sh = m.filter(ImageFilter.GaussianBlur(W * 0.022)).point(lambda v: int(v * 0.32))
sh = ImageChops.offset(sh, 0, int(W * 0.018))
out = bg.copy()
out.paste((14, 52, 150), (0, 0), sh)
# White -> very light blue fill
out.paste(vgrad((255, 255, 255), (214, 233, 255)), (0, 0), m)
out.paste((255, 255, 255), (0, 0), sp)

out.resize((1024, 1024), Image.LANCZOS).save(OUT)
print("saved", OUT)
