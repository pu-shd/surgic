"""OCR front-end: macOS Vision (primary) with Tesseract fallback.

``recognize(png_bytes)`` returns word boxes in pixel coordinates with the
origin at the top-left of the image.
"""
from __future__ import annotations

import io
import sys
from dataclasses import dataclass
from typing import Callable

from PIL import Image


@dataclass(frozen=True)
class OcrWord:
    text: str
    x0: int
    y0: int
    x1: int
    y1: int


OcrFn = Callable[[bytes], list[OcrWord]]


def _vision_available() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        import Vision  # noqa: F401
        import Quartz  # noqa: F401
    except ImportError:
        return False
    return True


def recognize_vision(png: bytes) -> list[OcrWord]:
    import Quartz
    import Vision
    from Foundation import NSData

    data = NSData.dataWithBytes_length_(png, len(png))
    src = Quartz.CGImageSourceCreateWithData(data, None)
    cg = Quartz.CGImageSourceCreateImageAtIndex(src, 0, None)
    width, height = Quartz.CGImageGetWidth(cg), Quartz.CGImageGetHeight(cg)

    req = Vision.VNRecognizeTextRequest.alloc().init()
    req.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    req.setUsesLanguageCorrection_(False)
    handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(cg, None)
    ok, err = handler.performRequests_error_([req], None)
    if not ok:
        raise RuntimeError("vision_ocr_failed")

    words: list[OcrWord] = []
    for obs in req.results() or []:
        cand = obs.topCandidates_(1)
        if not cand:
            continue
        cand = cand[0]
        line = str(cand.string())
        pos = 0
        for token in line.split():
            idx = line.index(token, pos)
            pos = idx + len(token)
            box, _ = cand.boundingBoxForRange_error_((idx, len(token)), None)
            if box is None:
                continue
            bb = box.boundingBox()
            # Vision: normalized, origin bottom-left.
            x0 = int(bb.origin.x * width)
            x1 = int((bb.origin.x + bb.size.width) * width + 0.999)
            y1 = int((1 - bb.origin.y) * height + 0.999)
            y0 = int((1 - bb.origin.y - bb.size.height) * height)
            words.append(OcrWord(token, max(x0, 0), max(y0, 0), min(x1, width), min(y1, height)))
    return words


def recognize_tesseract(png: bytes) -> list[OcrWord]:
    import pytesseract

    img = Image.open(io.BytesIO(png))
    d = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, config="--psm 3")
    words = []
    for i, t in enumerate(d["text"]):
        t = (t or "").strip()
        if not t or float(d["conf"][i]) < 0:
            continue
        x, y, w, h = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
        words.append(OcrWord(t, x, y, x + w, y + h))
    return words


def default_ocr(prefer: str = "auto") -> OcrFn:
    if prefer in ("auto", "vision") and _vision_available():
        return recognize_vision
    if prefer == "vision":
        raise RuntimeError("vision_unavailable")
    return recognize_tesseract
