# Unshield - Phishing Detector

Unshield checks **links, SMS/chat messages, emails (.eml) and QR codes** and explains *why* something
looks like phishing. It runs fully offline by rules (no data leaves your machine), with a CLI and a
small web UI. Built for the university community (English + Roman Urdu messages, Pakistani brands
such as HBL, EasyPaisa, JazzCash, NADRA, FBR, BISP, Daraz).

## Quick start (Kaise chalayen)

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1) Web UI
python app.py                       # open http://127.0.0.1:5000

# 2) Command line
python -m unshield url   "http://paypa1-secure-login.xyz/verify"
python -m unshield text  "Aap ka account foran block ho jaye ga, OTP bhejein"
python -m unshield text  @samples/smishing.txt
python -m unshield email samples/phishing_bank.eml
python -m unshield qr    samples/qr_phishing.png
python -m unshield --json url "https://bit.ly/abc"       # JSON output
# exit code: 0 = likely safe, 1 = suspicious, 2 = phishing   (useful in scripts)

# 3) Tests
python -m unittest discover -s tests -v
```

Gmail se email lene ke liye: mail kholein -> three dots -> **Download message** (.eml).

## How it works

Every analyzer returns a `Result` with a list of `Finding`s (rule id, explanation, points, evidence).
Points are added up to a 0-100 **risk score**; the worst link inside a message also raises the
message's score.

| Score | Verdict |
| --- | --- |
| 0 - 24 | LIKELY SAFE |
| 25 - 59 | SUSPICIOUS |
| 60 - 100 | PHISHING |

| Module | What it checks |
| --- | --- |
| `url_analyzer.py` | raw/obfuscated IP hosts, `user@host` trick, punycode/unicode homographs, brand impersonation (contains / look-alike letters / typo-squat), suspicious TLDs, shorteners, free hosting abuse, odd ports, no HTTPS, sensitive words, embedded redirect URLs, executable & double-extension downloads |
| `text_analyzer.py` | urgency, threats, reward bait, requests for OTP/PIN/CNIC/passwords (English + Roman Urdu), invisible characters, "call this number", + every link inside |
| `email_analyzer.py` | display-name spoofing, Reply-To / Return-Path mismatch, SPF/DKIM/DMARC results, HTML link text vs real href, password forms, hidden HTML, dangerous attachments, + body language + every link |
| `qr_analyzer.py` | decodes the image (OpenCV, several pre-processing passes), classifies payload (URL, SMS/tel, Wi-Fi, payment/Raast, app install...), scans embedded URLs, flags "quishing" |

All weights and word lists live in `unshield/data.py` and the `weights` in each analyzer. Tune them
with your own dataset.

## Security design of the tool itself

* Web app binds to `127.0.0.1`, 6 MB upload limit, strict CSP, no inline scripts.
* UI renders attacker-controlled text with `textContent` only (a malicious email cannot inject HTML/JS).
* Links are **never opened** unless you pass `--follow` (HEAD requests only, max 5 hops). In the web
  app this needs `UNSHIELD_ALLOW_FOLLOW=1`. The resolver refuses private/loopback/link-local targets (SSRF guard).
* Parsers are size-limited and wrapped so malformed emails/images cannot crash the app.

## Known limitations (write these in your report)

* Rule-based: new tricks need new rules; it can miss well-made phishing on a clean domain
  (e.g. a compromised legitimate site) and can flag unusual-but-legit links.
* No domain-age / WHOIS / reputation lookups (they need the network and third-party APIs).
* Brand list is small and manual; QR detection can't see a sticker pasted over a real QR.
* Scores are indicators, not guarantees.

## Ideas for next steps

1. Add reputation lookups (Google Safe Browsing, PhishTank/OpenPhish feeds, VirusTotal) behind an opt-in flag.
2. Domain age and TLS certificate checks (WHOIS/RDAP, certificate transparency).
3. Train a classifier (character n-grams on URLs + features from this tool) and compare it with the rules - good for a research section.
4. Browser extension / WhatsApp-Telegram bot front-end using the same `analyze_*` functions.
5. Collect a labelled dataset of university-themed phishing (fee challan, result, scholarship, HEC) and measure precision/recall.
