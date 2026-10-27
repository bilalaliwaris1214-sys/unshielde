"""Command line interface:  python -m unshield url|text|email|qr ..."""
from __future__ import annotations

import argparse
import json
import sys

from . import analyze_email, analyze_qr_image, analyze_text, analyze_url
from .models import Result

_COLORS = {"PHISHING": "\033[1;31m", "SUSPICIOUS": "\033[1;33m", "LIKELY SAFE": "\033[1;32m"}
_RESET = "\033[0m"


def _print(res: Result, indent: int = 0, color: bool = True) -> None:
    pad = "  " * indent
    if res.error:
        print(f"{pad}[error] {res.error}")
        return
    verdict = res.verdict
    tag = f"{_COLORS[verdict]}{verdict}{_RESET}" if color else verdict
    print(f"{pad}{res.kind.upper()}: {res.target}")
    print(f"{pad}  Risk score: {res.score}/100  ->  {tag}")
    for f in sorted(res.findings, key=lambda x: -x.weight):
        pts = f"+{f.weight}" if f.weight else " ."
        print(f"{pad}    [{pts:>3}] {f.message}")
        if f.evidence:
            print(f"{pad}          evidence: {f.evidence}")
    for c in res.children:
        print()
        _print(c, indent + 1, color)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="unshield", description="Unshield - phishing detector (links, messages, emails, QR codes)")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("url", help="analyse a link")
    s.add_argument("url")
    s.add_argument("--follow", action="store_true", help="follow redirects over the network (HEAD requests only)")
    s = sub.add_parser("text", help="analyse an SMS/chat message (text or @file.txt)")
    s.add_argument("text")
    s.add_argument("--follow", action="store_true")
    s = sub.add_parser("email", help="analyse a .eml file")
    s.add_argument("file")
    s.add_argument("--follow", action="store_true")
    s = sub.add_parser("qr", help="analyse a QR code image")
    s.add_argument("image")
    s.add_argument("--follow", action="store_true")

    a = p.parse_args(argv)
    try:
        if a.cmd == "url":
            res = analyze_url(a.url, follow=a.follow)
        elif a.cmd == "text":
            txt = open(a.text[1:], encoding="utf-8", errors="replace").read() if a.text.startswith("@") else a.text
            res = analyze_text(txt, follow=a.follow)
        elif a.cmd == "email":
            with open(a.file, "rb") as fh:
                res = analyze_email(fh.read(), follow=a.follow)
        else:
            res = analyze_qr_image(a.image, follow=a.follow)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        _print(res, color=sys.stdout.isatty() and not a.no_color)
    # exit code lets scripts/CI react: 0 safe, 1 suspicious, 2 phishing
    return {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2}[res.verdict]


if __name__ == "__main__":
    sys.exit(main())
