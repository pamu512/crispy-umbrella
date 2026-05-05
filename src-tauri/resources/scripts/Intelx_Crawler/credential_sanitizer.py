import re

HTML_TAG_RE = re.compile(r"<[^>]+>")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

def strip_html(s: str) -> str:
    """Remove HTML tags and control chars, then strip."""
    if s is None:
        return ""
    s = str(s)
    s = HTML_TAG_RE.sub("", s)
    s = CONTROL_CHARS_RE.sub("", s)
    return s.strip()

def clean_domain(domain: str) -> str:
    """Remove characters like quotes/angle brackets and common junk."""
    d = strip_html(domain)
    d = d.replace('"', "").replace("'", "").replace("<", "").replace(">", "").strip()
    d = re.sub(r'^.*target\s*=\s*_?blank\s*>', "", d, flags=re.I).strip()
    d = d.strip(" ,;|()[]{}")
    return d

def clean_username(user: str, keep_blank_literal: bool = False) -> str:
    """
    Clean username/email.
    If string looks like target="_blank">https..., by default drop _blank (return "").
    """
    u = strip_html(user)

    m = re.search(r'target\s*=\s*"_?([^"]+)"\s*>\s*(https?://\S+)?', u, flags=re.I)
    if m:
        extracted = m.group(1).strip()
        if extracted.lower() in ("blank", "_blank"):
            return extracted if keep_blank_literal else ""
        return extracted

    u = u.replace('"', "").replace("'", "").replace("<", "").replace(">", "").strip()
    u = u.strip(" ,;|()[]{}")

    if u.lower() in ("blank", "_blank"):
        return u if keep_blank_literal else ""

    return u

def clean_password(pw: str) -> str:
    """Basic cleanup for password string."""
    p = strip_html(pw)
    p = p.replace('"', "").replace("'", "").replace("<", "").replace(">", "").strip()
    p = p.strip(" ,;|()[]{}")
    return p

def is_likely_password(pw: str) -> bool:
    """
    Heuristic: reject obvious non-password garbage (HTML fragments, URLs).
    """
    if not pw:
        return False

    lowered = pw.lower()

    # HTML markers / leftovers
    if "<" in pw or ">" in pw:
        return False
    if "</" in lowered or "/>" in lowered:
        return False
    if "href=" in lowered or "target=" in lowered:
        return False

    # URLs / website-looking strings
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return False
    if lowered.startswith("//") or "www." in lowered:
        return False

    # length / whitespace checks
    if len(pw) > 80:
        return False
    if len(pw) < 3:
        return False
    if " " in pw:
        return False

    return True
