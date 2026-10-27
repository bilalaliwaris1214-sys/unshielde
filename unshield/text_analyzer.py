"""SMS / chat / email-body analysis: social-engineering language + every link inside."""
from __future__ import annotations

import re
from typing import Iterable, List

from .data import (
    CREDENTIAL_PHRASES, GENERIC_GREETINGS, REWARD_PHRASES, THREAT_PHRASES, URGENCY_PHRASES,
    URL_SHORTENERS,
)
from .models import Result
from .url_analyzer import analyze_url

MAX_TEXT_LEN = 100_000
MAX_LINKS = 20

_URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"'`]+)")
_SHORT_RE = re.compile(r"(?i)\b((?:%s)/[^\s<>\"'`]+)" % "|".join(re.escape(s) for s in URL_SHORTENERS))
_HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠﻿]")
_CALL_RE = re.compile(r"(?i)\b(?:call|whatsapp|contact|sms|text)\b[^\n]{0,40}?(\+?\d[\d\s\-()]{8,}\d)")


def _compile(phrases: Iterable[str]) -> List[re.Pattern]:
    return [re.compile(r"(?<![a-z0-9])" + re.escape(p) + r"(?![a-z0-9])", re.I) for p in phrases]


_URGENCY = _compile(URGENCY_PHRASES)
_CREDENTIAL = _compile(CREDENTIAL_PHRASES)
_REWARD = _compile(REWARD_PHRASES)
_THREAT = _compile(THREAT_PHRASES)


def _matches(patterns: List[re.Pattern], text: str) -> List[str]:
    found = []
    for p in patterns:
        m = p.search(text)
        if m:
            found.append(m.group(0).lower())
    return found


def extract_urls(text: str) -> List[str]:
    urls: List[str] = []
    for rx in (_URL_RE, _SHORT_RE):
        for m in rx.finditer(text):
            u = m.group(1).rstrip(".,;:!?)]}'\"")
            if u and u not in urls:
                urls.append(u)
    return urls[:MAX_LINKS]


def score_language(res: Result, text: str) -> dict:
    """Add language-based findings to `res`. Returns which categories fired."""
    fired = {}
    urg, cred, rew, thr = (_matches(p, text) for p in (_URGENCY, _CREDENTIAL, _REWARD, _THREAT))

    if urg:
        res.add("urgency", "Creates time pressure: " + ", ".join(urg[:4]), 8 if len(urg) == 1 else 15, ", ".join(urg[:4]))
    if cred:
        res.add("credential_request", "Asks for secrets/personal data (password, OTP, PIN, card, CNIC): " + ", ".join(cred[:4]), 20 if len(cred) == 1 else 30, ", ".join(cred[:4]))
    if rew:
        res.add("reward_bait", "Offers a prize/refund/grant (reward bait): " + ", ".join(rew[:4]), 15 if len(rew) == 1 else 25, ", ".join(rew[:4]))
    if thr:
        res.add("threat", "Uses threats (blocked account, legal action, penalty): " + ", ".join(thr[:4]), 8 if len(thr) == 1 else 15, ", ".join(thr[:4]))
    fired.update(urgency=bool(urg), credential=bool(cred), reward=bool(rew), threat=bool(thr))

    low = text.lower()
    for g in GENERIC_GREETINGS:
        if g in low:
            res.add("generic_greeting", "Generic greeting instead of your name", 5, g)
            break
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 25 and sum(c.isupper() for c in letters) / len(letters) > 0.6:
        res.add("shouting", "Mostly ALL-CAPS text (pressure tactic)", 5, text[:40])
    if _HIDDEN_CHARS.search(text):
        res.add("hidden_chars", "Contains invisible/zero-width or bidirectional-control characters (used to evade filters)", 10, "zero-width")
    m = _CALL_RE.search(text)
    if m:
        res.add("call_number", "Pushes you to call/message a phone number (vishing/smishing)", 10, m.group(1).strip())
    # pressure + a sensitive ask is far more dangerous than either alone
    if (urg or thr) and (cred or rew):
        res.add("pressure_plus_ask", "Combines pressure/threat with a request for data or a reward - the core phishing pattern", 15, "")
    return fired


def analyze_text(text: str, follow: bool = False) -> Result:
    text = (text or "").strip()
    res = Result("text", (text[:80] + "...") if len(text) > 80 else text)
    if not text:
        res.error = "Empty message"
        return res
    text = text[:MAX_TEXT_LEN]

    score_language(res, text)
    urls = extract_urls(text)
    if urls and any(f.code in ("urgency", "credential_request", "reward_bait", "threat") for f in res.findings):
        res.add("link_with_pressure", "Message pushes you toward a link using pressure or bait", 10, urls[0][:80])
    for u in urls:
        child = analyze_url(u, follow=follow)
        res.children.append(child)
    if len(urls) >= MAX_LINKS:
        res.add("many_links", f"{MAX_LINKS}+ links in one message", 5, "")
    return res
