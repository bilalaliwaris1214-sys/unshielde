"""URL / link analysis: purely offline, rule based (optional redirect following)."""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from .data import (
    ABUSED_HOSTING, BRANDS, BRAND_COMPANION_WORDS, MULTI_PART_SUFFIXES, REDIRECT_PARAMS,
    SENSITIVE_PATH_WORDS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS, URL_SHORTENERS,
)
from .models import Result

MAX_URL_LEN = 4096
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}
DOWNLOAD_EXT = (".exe", ".scr", ".apk", ".msi", ".bat", ".cmd", ".js", ".vbs", ".jar", ".iso", ".lnk", ".hta", ".ps1")
_LEET = str.maketrans("013457@$", "oleastas")


# --------------------------------------------------------------------------- helpers
def _tokens(s: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def _normalize_leet(s: str) -> str:
    return s.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def split_host(host: str) -> Tuple[str, str, List[str]]:
    """Return (registered_domain, label_without_suffix, subdomain_labels)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        reg_labels = labels[-3:]
        subs = labels[:-3]
        main = labels[-3]
    elif len(labels) >= 2:
        reg_labels = labels[-2:]
        subs = labels[:-2]
        main = labels[-2]
    else:
        return host, host, []
    return ".".join(reg_labels), main, subs


def registered_domain(host: str) -> str:
    return split_host(host)[0]


def _ip_from_obfuscated(host: str) -> Optional[str]:
    """Detect http://3232235777/ , http://0xC0A80001/ , http://0300.0250.0.1/ style hosts."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", host):
            return str(ipaddress.ip_address(int(host)))
        if re.fullmatch(r"0x[0-9a-f]{6,8}", host):
            return str(ipaddress.ip_address(int(host, 16)))
        if re.fullmatch(r"[0-9a-fx]+(\.[0-9a-fx]+){3}", host) and re.search(r"(^|\.)0[0-7]+|0x", host):
            octets = [int(p, 16) if p.startswith("0x") else int(p, 8) if p.startswith("0") and len(p) > 1 else int(p) for p in host.split(".")]
            if all(0 <= o <= 255 for o in octets):
                return ".".join(map(str, octets))
    except ValueError:
        return None
    return None


def _brand_name_matches(token: str, brand: str) -> bool:
    """True when `token` is the brand, or brand fused with a companion word (securepaypal)."""
    if token == brand:
        return True
    if len(brand) < 5:           # short brands: exact token only (avoids 'pta' in 'adapta')
        return False
    if token.startswith(brand) and token[len(brand):] in BRAND_COMPANION_WORDS:
        return True
    if token.endswith(brand) and token[: -len(brand)] in BRAND_COMPANION_WORDS:
        return True
    return False


# Cyrillic/Greek letters that look like Latin ones (used in homograph domains).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "ј": "j", "ӏ": "l", "ԁ": "d", "ɡ": "g", "һ": "h", "ԛ": "q", "ԝ": "w", "ν": "v", "ο": "o",
    "ρ": "p", "α": "a", "ι": "i", "κ": "k", "τ": "t", "ɑ": "a", "ο": "o", "ı": "i",
})


def homograph_skeleton(host: str) -> str:
    """Decode punycode and map look-alike letters to Latin, e.g. xn--pypal-4ve.com -> paypal.com."""
    try:
        decoded = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        decoded = host
    return decoded.lower().translate(_CONFUSABLES)


def find_brand_impersonation(host: str, skeleton: Optional[str] = None) -> List[Tuple[str, str, str]]:
    """Return [(brand, code, explanation)] for hosts that imitate a brand they don't own."""
    reg, main, subs = split_host(host)
    out: List[Tuple[str, str, str]] = []
    raw_tokens = _tokens(main) + [t for s in subs for t in _tokens(s)]
    skel_tokens: List[str] = []
    if skeleton and skeleton != host:
        _, s_main, s_subs = split_host(skeleton)
        skel_tokens = _tokens(s_main) + [t for s in s_subs for t in _tokens(s)]
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        hit = None
        # 0) homograph: after mapping look-alike letters the host spells the brand
        if skel_tokens and any(_brand_name_matches(t, brand) for t in skel_tokens):
            hit = ("lookalike_domain", f"host uses look-alike (unicode/punycode) letters to spell '{brand}' (real domain: {reg})")
        # 1) the brand name itself appears in the host
        if not hit and any(_brand_name_matches(t, brand) for t in raw_tokens):
            where = "subdomain" if any(_brand_name_matches(t, brand) for s in subs for t in _tokens(s)) else "domain name"
            hit = ("brand_in_host", f"'{brand}' appears in the {where}, but the real domain is {reg}")
        # 2) character-substitution lookalike (paypa1, g00gle, rnicrosoft)
        if not hit:
            for t in raw_tokens:
                n = _normalize_leet(t)
                if n != t and _brand_name_matches(n, brand):
                    hit = ("lookalike_domain", f"'{t}' imitates '{brand}' using look-alike characters (real domain: {reg})")
                    break
        # 3) typo-squat (paypall, gooogle) - only for longer brand names to limit false positives
        if not hit and len(brand) >= 6:
            limit = 1 if len(brand) < 9 else 2
            for t in raw_tokens:
                if len(t) >= len(brand) - 1 and t != brand and _levenshtein(t, brand) <= limit:
                    hit = ("typosquat_domain", f"'{t}' is a near-miss spelling of '{brand}' (real domain: {reg})")
                    break
        if hit:
            out.append((brand, hit[0], hit[1]))
    # keep it readable: strongest two only
    return out[:2]


# --------------------------------------------------------------------------- main analyzer
def normalize_url(raw: str) -> str:
    raw = (raw or "").strip().strip("<>\"'")
    if not raw:
        return raw
    if re.match(r"^[a-z][a-z0-9+.\-]*:", raw, re.I) and not re.match(r"^[a-z0-9.\-]+:\d+(/|$)", raw, re.I):
        return raw                       # already has a scheme (http:, javascript:, ...)
    if raw.startswith("//"):
        return "http:" + raw
    return "http://" + raw


def analyze_url(raw: str, follow: bool = False, _depth: int = 0) -> Result:
    original = (raw or "").strip()
    res = Result("url", original[:200])
    if not original:
        res.error = "Empty URL"
        return res
    if len(original) > MAX_URL_LEN:
        res.add("url_too_long", "Extremely long URL (possible obfuscation or overflow attempt)", 20, original[:60] + "...")
        original = original[:MAX_URL_LEN]

    url = normalize_url(original)
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        res.add("malformed_url", "URL is malformed and cannot be parsed safely", 15, original[:80])
        return res

    scheme = parts.scheme.lower()
    if scheme in DANGEROUS_SCHEMES:
        res.add("dangerous_scheme", f"'{scheme}:' links can run code or hide content instead of opening a website", 60, scheme + ":")
        return res
    if scheme not in ("http", "https"):
        res.add("unusual_scheme", f"Not a normal web link (scheme '{scheme}:')", 15, scheme + ":")
        return res
    if not host:
        res.add("malformed_url", "No hostname found in URL", 15, original[:80])
        return res

    # ---- connection / syntax tricks
    if scheme == "http":
        res.add("no_https", "Link uses plain HTTP (no encryption); real login pages use HTTPS", 10, "http://")
    if parts.username is not None or "@" in parts.netloc:
        res.add("userinfo_trick", "Contains '@' before the host: everything before it is ignored by the browser, a classic disguise", 30, parts.netloc[:80])
    if port not in (None, 80, 443):
        res.add("odd_port", f"Uses a non-standard port ({port})", 10, str(port))
    if "%" in host:
        res.add("encoded_host", "Hostname contains percent-encoding (used to hide the real address)", 20, host)

    # ---- IP address host
    ip = _ip_from_obfuscated(host)
    if ip:
        res.add("ip_host", f"Link goes to a raw IP address ({ip}) instead of a domain name", 40, host)
    # ---- unicode / punycode (homograph attacks)
    is_unicode = any(ord(c) > 127 for c in host)
    ascii_host = host
    if is_unicode:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = host
        res.add("unicode_host", f"Hostname contains non-ASCII characters (may impersonate another site): {ascii_host}", 30, host)
    elif "xn--" in host:
        try:
            decoded = host.encode("ascii").decode("idna")
        except UnicodeError:
            decoded = host
        res.add("punycode_host", f"Punycode hostname (shows as '{decoded}' in some browsers), common in look-alike attacks", 25, host)

    # the remaining checks work on the unicode-normalised ASCII host
    check_host = ascii_host if not ip else host
    reg, main, subs = split_host(check_host) if not ip else (host, host, [])
    trusted = reg in TRUSTED_DOMAINS
    tld = check_host.rsplit(".", 1)[-1] if "." in check_host else ""

    if not ip:
        if reg in URL_SHORTENERS:
            res.add("url_shortener", f"Link shortener ({reg}) hides the real destination - cannot be verified without opening it (use --follow)", 25, reg)
        if tld in SUSPICIOUS_TLDS:
            res.add("suspicious_tld", f"'.{tld}' is a low-cost TLD heavily used in phishing campaigns", 15, "." + tld)
        for abused in ABUSED_HOSTING:
            if check_host == abused or check_host.endswith("." + abused):
                res.add("abused_hosting", f"Hosted on a free/dynamic hosting service ({abused}) often used for fake pages", 12, abused)
                break
        if len(subs) >= 3:
            res.add("many_subdomains", f"{len(subs)} subdomain levels: the real domain ({reg}) is buried at the end", 10, check_host)
        encoded_host = is_unicode or "xn--" in check_host
        if main.count("-") >= 2 and not encoded_host:
            res.add("many_hyphens", "Several hyphens in the domain name (typical of fake 'secure-login-xxx' domains)", 8, main)
        if not encoded_host and sum(c.isdigit() for c in main) >= 3 and any(c.isalpha() for c in main):
            res.add("digits_in_domain", "Domain mixes letters with several digits", 5, main)
        skeleton = homograph_skeleton(check_host) if ("xn--" in check_host or is_unicode) else None
        weights = {"brand_in_host": 45, "lookalike_domain": 50, "typosquat_domain": 45}
        for brand, code, why in find_brand_impersonation(check_host, skeleton):
            res.add(code, "Brand impersonation: " + why, weights[code], brand)

    # ---- path / query analysis
    path = unquote(parts.path or "")
    query = parts.query or ""
    full_len = len(original)
    if full_len > 200:
        res.add("long_url", f"Very long URL ({full_len} characters)", 8, original[:50] + "...")
    elif full_len > 100:
        res.add("long_url", f"Long URL ({full_len} characters)", 4, original[:50] + "...")

    if not trusted:
        words = sorted({w for w in _tokens(path + " " + main + " " + " ".join(subs)) if w in SENSITIVE_PATH_WORDS})
        if words:
            res.add("sensitive_keywords", "Asks for account-style actions on an unfamiliar domain: " + ", ".join(words[:5]), 15 if len(words) >= 3 else 10, ",".join(words[:5]))
        if not ip:
            for brand, official in BRANDS.items():
                if reg in official or len(brand) < 5:
                    continue
                if brand in path.lower():
                    res.add("brand_in_path", f"Brand name '{brand}' used in the path of an unrelated domain ({reg})", 20, brand)
                    break
    lowered = path.lower()
    if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|bat|apk|vbs)$", lowered):
        res.add("double_extension", "Double file extension used to disguise an executable", 35, lowered.rsplit("/", 1)[-1][:60])
    elif lowered.endswith(DOWNLOAD_EXT):
        res.add("executable_download", "Link points directly at an executable/installer file", 25, lowered.rsplit("/", 1)[-1][:60])
    if len(re.findall(r"%[0-9a-fA-F]{2}", parts.path or "")) >= 6:
        res.add("heavy_encoding", "Path is heavily percent-encoded (can hide keywords)", 5, (parts.path or "")[:60])

    # ---- embedded redirect URL (open-redirect abuse)
    for key, values in parse_qs(query).items():
        if key.lower() in REDIRECT_PARAMS:
            for v in values:
                if re.match(r"^(https?:)?//", v, re.I):
                    res.add("embedded_redirect", f"Query parameter '{key}' contains another URL (redirect chain)", 15, v[:100])
                    if _depth < 2:
                        child = analyze_url(v, follow=False, _depth=_depth + 1)
                        child.target = "embedded: " + child.target
                        res.children.append(child)
                    break

    # ---- optional: follow redirects (network!)
    if follow and not ip and _depth < 1:
        chain = resolve_redirects(url)
        if len(chain) > 1:
            final = chain[-1]
            res.add("redirects", f"Redirects {len(chain) - 1} time(s) to {final[:80]}", 5 if len(chain) <= 3 else 12, " -> ".join(chain)[:200])
            if registered_domain(urlsplit(final).hostname or "") != reg:
                child = analyze_url(final, follow=False, _depth=_depth + 1)
                child.target = "final destination: " + child.target
                res.children.append(child)
    return res


# --------------------------------------------------------------------------- redirect resolver (optional)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # noqa: D401
        return None


def _is_public_host(host: str) -> bool:
    """SSRF guard: refuse private, loopback, link-local and reserved targets."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False
    return True


def resolve_redirects(url: str, max_hops: int = 5, timeout: float = 5.0) -> List[str]:
    """Follow HTTP redirects manually (HEAD only, never downloads content)."""
    chain = [url]
    opener = urllib.request.build_opener(_NoRedirect)
    for _ in range(max_hops):
        host = urlsplit(chain[-1]).hostname or ""
        if not host or not _is_public_host(host):
            break
        req = urllib.request.Request(chain[-1], method="HEAD", headers={"User-Agent": "Unshield/1.0 (+phishing-checker)"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                loc = resp.headers.get("Location")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") if 300 <= e.code < 400 else None
        except (urllib.error.URLError, socket.timeout, OSError, ValueError):
            break
        if not loc:
            break
        nxt = urljoin(chain[-1], loc)
        if nxt in chain:
            break
        chain.append(nxt)
    return chain
