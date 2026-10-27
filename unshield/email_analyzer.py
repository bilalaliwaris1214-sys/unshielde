"""Email analysis (.eml / raw RFC-822): headers, authentication, links, HTML tricks, attachments."""
from __future__ import annotations

import email
import email.policy
import re
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import List, Tuple, Union

from .data import BRANDS, DANGEROUS_ATTACHMENT_EXT, RISKY_ATTACHMENT_EXT
from .models import Result
from .text_analyzer import MAX_LINKS, extract_urls, score_language
from .url_analyzer import _tokens, analyze_url, registered_domain, _brand_name_matches
from urllib.parse import urlsplit

MAX_EMAIL_BYTES = 5 * 1024 * 1024
_HIDE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?!\.)|opacity\s*:\s*0(?!\.)", re.I)
_DOMAIN_LIKE = re.compile(r"(?i)^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#].*)?$")


class _HTMLScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: List[str] = []
        self.links: List[Tuple[str, str]] = []     # (href, anchor text)
        self.form_actions: List[str] = []
        self.has_password = False
        self.hidden_blocks = 0
        self.images = 0
        self._href = None
        self._anchor: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        if a.get("style") and _HIDE_RE.search(a["style"]):
            self.hidden_blocks += 1
        if tag == "a" and a.get("href"):
            self._href, self._anchor = a["href"], []
        elif tag == "form":
            self.form_actions.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password = True
        elif tag == "img":
            self.images += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _domain_of(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    return registered_domain(host) if host else ""


def _addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower().strip(">") if "@" in addr else ""


def _auth_results(msg) -> dict:
    out = {}
    blob = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b%s\s*=\s*([a-z]+)" % mech, blob, re.I)
        if m:
            out[mech] = m.group(1).lower()
    if "spf" not in out:
        rs = str(msg.get("Received-SPF", "")).strip().split(" ", 1)[0].lower()
        if rs in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
            out["spf"] = rs
    return out


def analyze_email(raw: Union[bytes, str], follow: bool = False) -> Result:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if not raw or not raw.strip():
        r = Result("email", "(empty)")
        r.error = "Empty email"
        return r
    if len(raw) > MAX_EMAIL_BYTES:
        r = Result("email", "(too large)")
        r.error = "Email larger than 5 MB - refusing to parse"
        return r

    msg = email.message_from_bytes(raw, policy=email.policy.default)
    subject = str(msg.get("Subject", "") or "")
    disp_name, from_addr = parseaddr(str(msg.get("From", "") or ""))
    from_dom_full = _addr_domain(from_addr)
    from_reg = registered_domain(from_dom_full) if from_dom_full else ""
    res = Result("email", f"{subject[:60] or '(no subject)'}  <{from_addr or 'unknown sender'}>")

    # ------------------------------------------------------------ sender identity
    if not from_addr:
        res.add("no_sender", "No parsable From address", 15, "")
    else:
        sender = analyze_url("https://" + from_dom_full)
        copy_codes = {"brand_in_host", "lookalike_domain", "typosquat_domain", "punycode_host", "unicode_host",
                      "suspicious_tld", "ip_host", "abused_hosting", "many_hyphens"}
        for f in sender.findings:
            if f.code in copy_codes:
                res.add("sender_" + f.code, "Sender domain: " + f.message, f.weight, f.evidence)

    # display name pretending to be a brand / another address
    if disp_name and from_reg:
        for brand, official in BRANDS.items():
            if from_reg in official:
                continue
            if any(_brand_name_matches(t, brand) for t in _tokens(disp_name)):
                res.add("display_name_spoof", f"Display name says '{disp_name}' but the email really comes from {from_reg}", 30, disp_name)
                break
        m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", disp_name)
        if m and registered_domain(m.group(1).lower()) != from_reg:
            res.add("display_name_address", f"Display name shows another address ({m.group(0)}) than the real sender", 30, m.group(0))

    # reply-to / return-path mismatches
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "") or ""))
    if reply_addr and from_reg and registered_domain(_addr_domain(reply_addr)) != from_reg:
        res.add("reply_to_mismatch", f"Replies go to a different domain ({_addr_domain(reply_addr)}) than the sender ({from_reg})", 20, reply_addr)
    _, rp_addr = parseaddr(str(msg.get("Return-Path", "") or ""))
    if rp_addr and from_reg and registered_domain(_addr_domain(rp_addr)) != from_reg:
        res.add("return_path_mismatch", f"Return-Path domain ({_addr_domain(rp_addr)}) differs from the From domain ({from_reg})", 10, rp_addr)

    # ------------------------------------------------------------ SPF / DKIM / DMARC
    auth = _auth_results(msg)
    weights = {"dmarc": 25, "spf": 20, "dkim": 15}
    for mech, val in auth.items():
        if val in ("fail", "permerror"):
            res.add(f"{mech}_fail", f"{mech.upper()} check FAILED: the sender is not authorised to use this domain", weights[mech], f"{mech}={val}")
        elif val in ("softfail", "temperror"):
            res.add(f"{mech}_softfail", f"{mech.upper()} check soft-failed", weights[mech] // 2, f"{mech}={val}")
    if not auth:
        res.add("no_auth_results", "No SPF/DKIM/DMARC results found in the headers (cannot verify sender)", 5, "")

    # ------------------------------------------------------------ body
    plain_parts: List[str] = []
    html_scans: List[_HTMLScan] = []
    attachments: List[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if fname or part.get_content_disposition() == "attachment":
            attachments.append(fname or "(unnamed)")
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError, KeyError):
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            s = _HTMLScan()
            try:
                s.feed(content)
                s.close()
            except Exception:  # malformed HTML must never crash the analyzer
                pass
            html_scans.append(s)
        elif ctype == "text/plain":
            plain_parts.append(content)

    body_text = "\n".join(plain_parts + [" ".join(s.text) for s in html_scans])
    score_language(res, subject + "\n" + body_text)

    # HTML-specific tricks
    link_urls: List[str] = []
    for s in html_scans:
        for href, anchor in s.links:
            if href.lower().startswith(("http://", "https://")):
                link_urls.append(href)
                m = _DOMAIN_LIKE.match(anchor.strip())
                if m and registered_domain(m.group(1).lower()) != _domain_of(href):
                    res.add("link_text_mismatch", f"Link text shows '{anchor[:50]}' but really goes to {_domain_of(href) or href[:40]}", 30, f"{anchor[:40]} -> {href[:60]}")
            elif href.lower().startswith(("javascript:", "data:")):
                res.add("dangerous_link", "HTML link uses a javascript:/data: scheme", 40, href[:60])
        if s.has_password:
            res.add("password_form", "Email body contains a password input form (real companies never ask for passwords inside an email)", 40, "<input type=password>")
        for action in s.form_actions:
            if action.lower().startswith("http"):
                res.add("form_posts_external", "Embedded form submits data to an external server", 25, action[:80])
        if s.hidden_blocks:
            res.add("hidden_html", f"{s.hidden_blocks} element(s) hidden with CSS (can be used to slip past spam filters)", 8, "display:none / font-size:0")
        if s.images and len(" ".join(s.text).strip()) < 40:
            res.add("image_only", "Email is almost entirely images (hides text from filters)", 8, f"{s.images} image(s)")

    # ------------------------------------------------------------ attachments
    for name in attachments:
        low = name.lower()
        ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
        if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|bat|vbs|cmd|com|lnk)$", low):
            res.add("double_extension", f"Attachment '{name}' hides an executable behind a document-style name", 40, name)
        elif ext in DANGEROUS_ATTACHMENT_EXT:
            res.add("dangerous_attachment", f"Attachment '{name}' is an executable/script type ({ext})", 40, name)
        elif ext in (".html", ".htm", ".svg"):
            res.add("html_attachment", f"Attachment '{name}' is an HTML/SVG file (often used to build fake login pages offline)", 25, name)
        elif ext in RISKY_ATTACHMENT_EXT:
            res.add("risky_attachment", f"Attachment '{name}' ({ext}) can carry malware or links; open only if you expected it", 8, name)

    # ------------------------------------------------------------ every link
    urls = list(dict.fromkeys(link_urls + extract_urls(body_text)))[:MAX_LINKS]
    for u in urls:
        res.children.append(analyze_url(u, follow=follow))
    return res
