"""QR code ("quishing") analysis: decode the image, classify the payload, scan any URL inside."""
from __future__ import annotations

import re
from typing import List, Optional, Union

import cv2
import numpy as np

from .models import Result
from .url_analyzer import analyze_url

MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 25_000_000


def _variants(img: np.ndarray):
    """Yield progressively more aggressive pre-processed versions of the image."""
    yield img
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    yield cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)   # quiet zone
    for scale in (2.0, 0.5):
        yield cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC if scale > 1 else cv2.INTER_AREA)
    yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10)
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield otsu


def decode_qr(data: Union[bytes, str]) -> List[str]:
    """Return every QR payload found in an image (path or raw bytes)."""
    if isinstance(data, str):
        with open(data, "rb") as fh:
            data = fh.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("Image larger than 8 MB")
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Not a readable image (PNG/JPG/BMP/WEBP expected)")
    if img.shape[0] * img.shape[1] > MAX_PIXELS:
        raise ValueError("Image resolution too large")

    detector = cv2.QRCodeDetector()
    for variant in _variants(img):
        found: List[str] = []
        try:
            ok, decoded, _, _ = detector.detectAndDecodeMulti(variant)
            if ok:
                found = [d for d in decoded if d]
        except cv2.error:
            pass
        if not found:
            try:
                single, _, _ = detector.detectAndDecode(variant)
                if single:
                    found = [single]
            except cv2.error:
                pass
        if found:
            return list(dict.fromkeys(found))
    return []


def analyze_qr_payload(payload: str, follow: bool = False) -> Result:
    """Classify a decoded QR string (also usable without an image, e.g. from a phone scanner)."""
    p = payload.strip()
    res = Result("qr", p[:120])
    low = p.lower()

    if re.match(r"(?i)^(https?://|www\.)", p) or re.match(r"(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(/|$)", p):
        url_res = analyze_url(p, follow=follow)
        res.findings = list(url_res.findings)      # flatten: one result, not parent + child
        res.children = url_res.children
        res.error = url_res.error
        res.add("qr_contains_url", "QR contains a web link - always check the address before opening", 0, p[:100])
        if url_res.score >= 25:
            # a QR hides the address from the user and bypasses email/SMS link filters
            res.add("quishing_risk", "Suspicious link delivered as a QR code (QR hides the address and bypasses link filters)", 15, "")
        return res
    if low.startswith(("tel:", "sms:", "smsto:", "mms:", "mmsto:")):
        res.add("qr_call_sms", "QR starts a call or pre-written SMS (premium-rate/vishing risk)", 30, p[:80])
    elif low.startswith("mailto:"):
        res.add("qr_mail", "QR opens a pre-filled email", 10, p[:80])
    elif low.startswith("wifi:"):
        res.add("qr_wifi", "QR joins a Wi-Fi network - only join networks you trust", 10, re.sub(r"P:[^;]*", "P:***", p)[:80])
        if re.search(r"T:(nopass|);", p, re.I) or "T:nopass" in p:
            res.add("qr_open_wifi", "QR connects to an OPEN (unencrypted) Wi-Fi network", 15, "T:nopass")
    elif low.startswith(("upi:", "bitcoin:", "ethereum:", "litecoin:", "monero:", "tron:")):
        res.add("qr_payment", "QR triggers a payment - fake QR stickers pasted over real ones are a common scam", 30, p[:80])
    elif p.startswith("000201") and "5802" in p:
        res.add("qr_emv_payment", "Payment QR (Raast/EMV style). Verify the merchant name shown in your banking app matches the shop before paying", 20, p[:40] + "...")
    elif low.startswith(("market:", "intent:", "itms-services:", "itms-apps:")) or low.endswith(".apk"):
        res.add("qr_app_install", "QR tries to install an app outside the normal store flow", 40, p[:80])
    elif low.startswith(("begin:vcard", "mecard:")):
        res.add("qr_contact", "QR adds a contact card", 5, p[:40])
    elif low.startswith(("javascript:", "data:", "file:")):
        res.add("qr_dangerous", "QR contains a script/data/file scheme", 60, p[:60])
    else:
        res.add("qr_plain_text", "QR contains plain text (no link detected)", 0, p[:80])
    return res


def analyze_qr_image(data: Union[bytes, str], follow: bool = False) -> Result:
    try:
        payloads = decode_qr(data)
    except (ValueError, OSError) as e:
        res = Result("qr", "(image)")
        res.error = str(e)
        return res
    if not payloads:
        res = Result("qr", "(image)")
        res.error = "No QR code could be detected in this image (try a sharper, closer, well-lit picture)"
        return res
    if len(payloads) == 1:
        return analyze_qr_payload(payloads[0], follow=follow)
    # several codes in one image -> combined result (a sticker pasted over a real code is suspicious)
    res = Result("qr", f"{len(payloads)} QR codes in one image")
    res.add("multiple_qr", "More than one QR code in the image - check that a fake sticker is not placed over the real one", 15, "")
    for p in payloads:
        res.children.append(analyze_qr_payload(p, follow=follow))
    return res
