"""Static knowledge used by the detectors. Extend these lists as you learn new attacks."""

# brand keyword -> official registered domains. A host that CONTAINS the keyword
# (or looks like it) but is NOT one of these domains is treated as impersonation.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.com.pk", "gmail.com", "goo.gl", "youtube.com", "googleapis.com"},
    "gmail": {"gmail.com", "google.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amzn.to"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "tiktok": {"tiktok.com"},
    "binance": {"binance.com"},
    "daraz": {"daraz.pk", "daraz.com", "daraz.com.bd"},
    "easypaisa": {"easypaisa.com.pk", "telenor.com.pk"},
    "jazzcash": {"jazzcash.com.pk", "jazz.com.pk"},
    "hbl": {"hbl.com"},
    "ubl": {"ubldigital.com", "ubl.com.pk"},
    "meezan": {"meezanbank.com"},
    "nadra": {"nadra.gov.pk"},
    "fbr": {"fbr.gov.pk", "iris.fbr.gov.pk"},
    "ehsaas": {"ehsaas.gov.pk"},
    "bisp": {"bisp.gov.pk"},
    "pta": {"pta.gov.pk"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

# Domains we never flag as brand impersonation (they ARE the brand).
TRUSTED_DOMAINS = set().union(*BRANDS.values())

# Words attackers glue onto a brand name ("securepaypal", "appleid", "amazonsupport").
BRAND_COMPANION_WORDS = {
    "support", "secure", "security", "login", "signin", "verify", "verification", "id", "account",
    "accounts", "service", "services", "online", "help", "helpdesk", "pay", "payment", "payments",
    "bank", "banking", "update", "team", "care", "center", "centre", "billing", "wallet", "official",
    "my", "get", "mail", "web", "app", "portal", "alert", "alerts", "recovery", "customer", "refund",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "lnkd.in", "t.ly", "v.gd",
}

# TLDs that are cheap/free and over-represented in phishing campaigns.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work", "loan",
    "country", "kim", "men", "party", "review", "science", "stream", "download", "racing",
    "icu", "cyou", "buzz", "monster", "rest", "support", "sbs", "cfd",
}

# Second-level suffixes where the registered domain is 3 labels (example.com.pk).
MULTI_PART_SUFFIXES = {
    "com.pk", "edu.pk", "gov.pk", "org.pk", "net.pk", "co.uk", "org.uk", "ac.uk",
    "com.au", "co.in", "com.bd", "co.za", "com.br", "com.tr", "com.sa", "com.ae",
}

# Free hosting / dynamic DNS / tunnelling services often abused to host fake pages.
ABUSED_HOSTING = {
    "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com", "netlify.app",
    "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "github.io",
    "glitch.me", "herokuapp.com", "ngrok.io", "ngrok-free.app", "duckdns.org", "no-ip.com",
    "r2.dev", "weeblysite.com", "godaddysites.com", "sites.google.com", "forms.gle",
}

SENSITIVE_PATH_WORDS = {
    "login", "signin", "sign-in", "verify", "verification", "update", "secure", "account",
    "password", "passwd", "confirm", "banking", "wallet", "recover", "unlock", "suspend",
    "authenticate", "validate", "billing", "invoice", "payment", "pay",
}

# Redirect-style query parameters that often hide the real destination.
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "next", "goto", "target", "dest", "link", "continue", "return", "returnurl", "u"}

# Phrases (lowercase). English + Roman Urdu, since local scams mix both.
URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "within 24 hours", "within 48 hours", "final notice",
    "last warning", "expires today", "limited time", "account will be", "will be blocked",
    "will be suspended", "will be closed", "will be deactivated", "suspended", "verify now",
    "verify your account", "unusual activity", "unauthorized login", "security alert",
    "foran", "fori", "turant", "jaldi", "abhi", "block ho", "band ho jaye", "band kar di", "24 ghante",
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password", "update your password", "verify your identity",
    "confirm your identity", "login to your account", "sign in to your account", "provide your",
    "card number", "cvv", "pin code", "your pin", "otp", "one time password", "one-time password",
    "security code", "cnic", "account number", "iban", "mother's maiden", "bank details",
    "password batao", "pin batao", "otp batao", "otp share", "code share", "apna pin", "apni detail",
]

REWARD_PHRASES = [
    "you have won", "you've won", "congratulations", "claim your prize", "claim your reward",
    "free gift", "lottery", "lucky winner", "cash prize", "gift card", "refund", "tax refund",
    "inam", "inaam", "jeet", "mubarak ho", "winner", "ehsaas", "bisp", "benazir", "grant approved",
    "double your", "guaranteed profit", "investment opportunity", "crypto giveaway",
]

THREAT_PHRASES = [
    "legal action", "arrest", "police", "court", "fine", "penalty", "terminated", "blocked",
    "locked", "frozen", "compromised", "hacked", "fir", "case darj", "giraftar",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear client", "dear member", "dear account holder", "dear sir/madam", "valued customer"]

DANGEROUS_ATTACHMENT_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".hta", ".chm", ".reg", ".dll",
}
RISKY_ATTACHMENT_EXT = {".html", ".htm", ".svg", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm", ".one", ".pdf"}
