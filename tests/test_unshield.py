"""Run:  python -m unittest discover -s tests -v"""
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from unshield import analyze_email, analyze_qr_image, analyze_qr_payload, analyze_text, analyze_url  # noqa: E402
from unshield.cli import main as cli_main  # noqa: E402
from unshield.url_analyzer import _is_public_host, find_brand_impersonation, split_host  # noqa: E402

SAMPLES = ROOT / "samples"


def codes(res):
    return {f.code for f in res.findings}


class UrlTests(unittest.TestCase):
    def test_legit_sites_are_clean(self):
        for u in ["https://www.google.com/search?q=cyber", "https://github.com/user/repo",
                  "https://www.paypal.com/signin", "https://www.hbl.com/login",
                  "https://www.sau.edu.pk", "https://www.daraz.pk/products/phone-i123.html",
                  "https://pineapple.com", "https://applebees.com"]:
            with self.subTest(url=u):
                self.assertEqual(analyze_url(u).verdict, "LIKELY SAFE", analyze_url(u).to_dict())

    def test_phishing_urls_detected(self):
        for u, must in [
            ("http://paypa1-secure-login.xyz/verify/account", "lookalike_domain"),
            ("https://paypal.com.evil-site.top/login", "brand_in_host"),
            ("http://192.168.1.5/bank/login.php", "ip_host"),
            ("http://3232235777/login", "ip_host"),
            ("https://xn--pypal-4ve.com/signin", "lookalike_domain"),
            ("https://accounts.google.com@evil.example.top/", "userinfo_trick"),
            ("http://easypaisa-verify.xyz/login", "brand_in_host"),
            ("https://example.com/files/invoice.pdf.exe", "double_extension"),
            ("javascript:alert(1)", "dangerous_scheme"),
        ]:
            with self.subTest(url=u):
                r = analyze_url(u)
                self.assertIn(must, codes(r))
                self.assertGreaterEqual(r.score, 25)

    def test_typosquat_and_leet(self):
        self.assertTrue(find_brand_impersonation("gooogle.com"))
        self.assertTrue(find_brand_impersonation("micr0soft-support.com"))
        self.assertFalse(find_brand_impersonation("microsoft.com"))
        self.assertFalse(find_brand_impersonation("apply.com"))        # 'apple' is short: no typo-squat rule

    def test_split_host_multipart_suffix(self):
        self.assertEqual(split_host("portal.sau.edu.pk")[0], "sau.edu.pk")
        self.assertEqual(split_host("a.b.example.com")[0], "example.com")

    def test_shortener_flagged_but_not_phishing(self):
        r = analyze_url("https://bit.ly/abc123")
        self.assertIn("url_shortener", codes(r))
        self.assertEqual(r.verdict, "SUSPICIOUS")

    def test_embedded_redirect_creates_child(self):
        r = analyze_url("https://example.com/out?url=http://paypa1-login.top/x")
        self.assertIn("embedded_redirect", codes(r))
        self.assertTrue(r.children and r.children[0].score >= 25)
        self.assertGreaterEqual(r.score, r.children[0].score)

    def test_bad_input_never_crashes(self):
        for u in ["", "   ", "http://", "http://[::1", "ht!tp://x", "a" * 10000, "http://%zz.com", "\x00\x01"]:
            with self.subTest(url=u[:20]):
                analyze_url(u).to_dict()

    def test_ssrf_guard_blocks_private_hosts(self):
        self.assertFalse(_is_public_host("127.0.0.1"))
        self.assertFalse(_is_public_host("169.254.169.254"))
        self.assertFalse(_is_public_host("10.0.0.5"))


class TextTests(unittest.TestCase):
    def test_roman_urdu_smishing(self):
        r = analyze_text((SAMPLES / "smishing.txt").read_text(encoding="utf-8"))
        self.assertEqual(r.verdict, "PHISHING")
        self.assertTrue({"urgency", "credential_request", "reward_bait"} <= codes(r))
        self.assertTrue(r.children)

    def test_normal_message_is_safe(self):
        r = analyze_text("Hi Bilal, class kal 10 baje hai. Notes yahan hain: https://github.com/sau/notes")
        self.assertEqual(r.verdict, "LIKELY SAFE", r.to_dict())

    def test_otp_alone_is_flagged_but_not_overreacted(self):
        r = analyze_text("Your OTP is 123456. Do not share it with anyone.")
        self.assertLess(r.score, 60)

    def test_hidden_chars_and_empty(self):
        self.assertIn("hidden_chars", codes(analyze_text("verify​ your​ account")))
        self.assertIsNotNone(analyze_text("   ").error)


class EmailTests(unittest.TestCase):
    def test_phishing_sample(self):
        r = analyze_email((SAMPLES / "phishing_bank.eml").read_bytes())
        self.assertEqual(r.verdict, "PHISHING")
        need = {"display_name_spoof", "reply_to_mismatch", "dmarc_fail", "spf_fail", "link_text_mismatch",
                "password_form", "double_extension", "sender_brand_in_host"}
        self.assertTrue(need <= codes(r), need - codes(r))

    def test_legit_sample(self):
        r = analyze_email((SAMPLES / "legit_newsletter.eml").read_bytes())
        self.assertEqual(r.verdict, "LIKELY SAFE", r.to_dict())

    def test_garbage_and_limits(self):
        self.assertIsNotNone(analyze_email(b"").error)
        self.assertIsNotNone(analyze_email(b"x" * (5 * 1024 * 1024 + 1)).error)
        analyze_email(b"\xff\xfe\x00not an email at all").to_dict()


class QrTests(unittest.TestCase):
    def test_phishing_qr(self):
        r = analyze_qr_image(str(SAMPLES / "qr_phishing.png"))
        self.assertEqual(r.verdict, "PHISHING")
        self.assertIn("quishing_risk", codes(r))

    def test_safe_qr(self):
        self.assertEqual(analyze_qr_image(str(SAMPLES / "qr_safe.png")).verdict, "LIKELY SAFE")

    def test_sms_qr(self):
        self.assertIn("qr_call_sms", codes(analyze_qr_image(str(SAMPLES / "qr_sms.png"))))

    def test_payload_classifier(self):
        self.assertIn("qr_payment", codes(analyze_qr_payload("bitcoin:bc1qexample?amount=1")))
        self.assertIn("qr_open_wifi", codes(analyze_qr_payload("WIFI:T:nopass;S:Free;;")))
        self.assertIn("qr_app_install", codes(analyze_qr_payload("market://details?id=com.fake")))
        self.assertEqual(analyze_qr_payload("hello world").verdict, "LIKELY SAFE")

    def test_non_image_and_blank_image(self):
        self.assertIsNotNone(analyze_qr_image(b"this is not an image").error)
        import cv2, numpy as np
        ok, buf = cv2.imencode(".png", np.full((100, 100, 3), 255, np.uint8))
        self.assertIn("No QR", analyze_qr_image(buf.tobytes()).error)


class CliAndApiTests(unittest.TestCase):
    def test_cli_exit_codes_and_json(self):
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["--no-color", "url", "https://www.google.com"]), 0)
            self.assertEqual(cli_main(["--no-color", "url", "http://paypa1-secure-login.xyz/verify"]), 2)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            cli_main(["--json", "url", "https://bit.ly/x"])
        finally:
            sys.stdout = old
        self.assertEqual(json.loads(out.getvalue())["verdict"], "SUSPICIOUS")

    def test_flask_api(self):
        from app import create_app
        c = create_app().test_client()
        r = c.post("/api/url", json={"url": "http://paypa1-secure-login.xyz/verify"})
        self.assertEqual(r.get_json()["verdict"], "PHISHING")
        r = c.post("/api/text", json={"text": "Aap ka account foran block hoga, OTP bhejein"})
        self.assertIn(r.get_json()["verdict"], ("SUSPICIOUS", "PHISHING"))
        r = c.post("/api/email", data={"file": (io.BytesIO((SAMPLES / "phishing_bank.eml").read_bytes()), "x.eml")})
        self.assertEqual(r.get_json()["verdict"], "PHISHING")
        r = c.post("/api/qr", data={"file": (io.BytesIO((SAMPLES / "qr_phishing.png").read_bytes()), "q.png")})
        self.assertEqual(r.get_json()["verdict"], "PHISHING")
        self.assertEqual(c.post("/api/qr").status_code, 400)
        self.assertIn("default-src 'self'", c.get("/").headers["Content-Security-Policy"])

    def test_follow_is_disabled_by_default_in_api(self):
        from app import create_app
        c = create_app().test_client()
        # even if a client asks for follow=1, the server ignores it unless UNSHIELD_ALLOW_FOLLOW=1
        r = c.post("/api/url?follow=1", json={"url": "http://127.0.0.1:1/"})
        self.assertNotIn("redirects", {f["code"] for f in r.get_json()["findings"]})


if __name__ == "__main__":
    unittest.main()
