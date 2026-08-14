import io
import random
import string

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont


def _code(length=6):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def _font(size):
    candidates = (
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    )
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _watermark_layer(size, lines, scale):
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    font = _font(max(11, int(15 * scale)))
    text = "   ".join(lines)
    box = draw.textbbox((0, 0), text, font=font)
    width = box[2] - box[0]
    height = box[3] - box[1]
    x = (size[0] - width) / 2
    y = (size[1] - height) / 2
    fill = (220, 220, 220, 85)
    spacing = int(130 * scale)
    for offset in range(-3, 4):
        draw.text((x, y + offset * spacing), text, font=font, fill=fill)
    return layer.rotate(28, expand=False)


def render_pdf(data, lines, scale=2.2, quality=88):
    pdf = pdfium.PdfDocument(data)
    pages = []
    try:
        for page in pdf:
            bitmap = page.render(scale=scale)
            img = bitmap.to_pil().convert("RGBA")
            wm = _watermark_layer(img.size, lines, scale)
            combined = Image.alpha_composite(img, wm).convert("RGB")
            buf = io.BytesIO()
            combined.save(buf, format="JPEG", quality=quality)
            pages.append(buf.getvalue())
    finally:
        pdf.close()
    return pages


def render_pdf_to_pdf(data, lines, scale=2.2, quality=88):
    pdf = pdfium.PdfDocument(data)
    images = []
    try:
        for page in pdf:
            bitmap = page.render(scale=scale)
            img = bitmap.to_pil().convert("RGBA")
            wm = _watermark_layer(img.size, lines, scale)
            combined = Image.alpha_composite(img, wm).convert("RGB")
            images.append(combined)
    finally:
        pdf.close()
    if not images:
        return b""
    buf = io.BytesIO()
    images[0].save(buf, format="PDF", save_all=True, append_images=images[1:], resolution=72.0)
    return buf.getvalue()