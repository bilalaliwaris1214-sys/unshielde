"""Unshield web app.  Run:  python app.py   ->  http://127.0.0.1:5000

Security notes (this is a security tool, so the app itself is hardened):
  * binds to 127.0.0.1 only by default
  * 6 MB upload limit, strict Content-Security-Policy, no inline scripts
  * the browser UI renders results with textContent only (no HTML injection from malicious emails)
  * redirect-following is OFF unless UNSHIELD_ALLOW_FOLLOW=1 (and blocks private IPs: SSRF guard)
"""
import os

from flask import Flask, jsonify, render_template, request

from unshield import analyze_email, analyze_qr_image, analyze_text, analyze_url

ALLOW_FOLLOW = os.environ.get("UNSHIELD_ALLOW_FOLLOW") == "1"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        return render_template("index.html", allow_follow=ALLOW_FOLLOW)

    def _follow() -> bool:
        return ALLOW_FOLLOW and request.values.get("follow") == "1"

    def _json_field(name: str) -> str:
        data = request.get_json(silent=True) or {}
        return str(data.get(name, "") or "")

    @app.post("/api/url")
    def api_url():
        return jsonify(analyze_url(_json_field("url"), follow=_follow()).to_dict())

    @app.post("/api/text")
    def api_text():
        return jsonify(analyze_text(_json_field("text"), follow=_follow()).to_dict())

    @app.post("/api/email")
    def api_email():
        f = request.files.get("file")
        raw = f.read() if f else _json_field("raw").encode("utf-8", "replace")
        return jsonify(analyze_email(raw, follow=_follow()).to_dict())

    @app.post("/api/qr")
    def api_qr():
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "Upload a QR image in the 'file' field"}), 400
        return jsonify(analyze_qr_image(f.read(), follow=_follow()).to_dict())

    @app.errorhandler(413)
    def too_big(_e):
        return jsonify({"error": "File too large (limit 6 MB)"}), 413

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("UNSHIELD_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
