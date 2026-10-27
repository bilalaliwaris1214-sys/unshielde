"""Generate sample QR images (needs OpenCV >= 4.x with QRCodeEncoder)."""
import cv2
import numpy as np
from pathlib import Path

out = Path(__file__).parent / "samples"
out.mkdir(exist_ok=True)

def make(text: str, name: str) -> None:
    enc = cv2.QRCodeEncoder.create()
    qr = enc.encode(text)
    qr = cv2.copyMakeBorder(qr, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    cv2.imwrite(str(out / name), qr)

make("http://parking-fine-pay.top/pay?id=44821&redirect=https://bit.ly/3xYz", "qr_phishing.png")
make("https://www.sau.edu.pk/", "qr_safe.png")
make("smsto:+923001234567:Send STOP to unsubscribe", "qr_sms.png")
print("samples written to", out)
