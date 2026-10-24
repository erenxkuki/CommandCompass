from __future__ import annotations

import re

SECRET_PATTERNS = [
    # key=value style
    re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*([^\s'\";|&]+)",
        re.IGNORECASE,
    ),
    # Authorization header
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._\-]+)"),
    # common token prefixes
    re.compile(r"(sk-[A-Za-z0-9]{10,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{10,})"),
    re.compile(r"(gho_[A-Za-z0-9]{10,})"),
    re.compile(r"(github_pat_[A-Za-z0-9_]{10,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"(xox[baprs]-[A-Za-z0-9-]{10,})"),
    # URL userinfo
    re.compile(r"(https?://)([^/\s:@]+):([^/\s@]+)@"),
    # private key paths
    re.compile(r"(/[^ \s]*id_rsa\b)"),
    re.compile(r"(/[^ \s]*\.pem\b)"),
]

REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    if not text:
        return text
    result = text
    for pat in SECRET_PATTERNS:
        # For patterns with groups, replace group 2 or whole? We'll replace captured secret group if groups else whole match
        def repl(m: re.Match) -> str:
            if m.lastindex and m.lastindex >= 2:
                # keep prefix groups, redact last group
                m.group(0)[: m.start(m.lastindex) - m.start(0)]  # rough
                # rebuild: groups before last + REDACTED + groups after (none)
                before = m.group(0)[: m.start(m.lastindex) - m.start(0)]
                return before + REDACTED
            # if group1 is secret prefix? handle specific
            return REDACTED

        # Simpler: handle known patterns individually
        result = pat.sub(lambda m: _redact_match(m), result)
    return result


def _redact_match(m: re.Match) -> str:
    # If pattern has 2+ groups, redact the last group; else redact entire match
    if m.lastindex and m.lastindex >= 2:
        # reconstruct with last group replaced
        s = m.group(0)
        last = m.group(m.lastindex)
        idx = s.rfind(last)
        if idx != -1:
            return s[:idx] + REDACTED + s[idx + len(last) :]
        return s
    # single group secret
    if m.lastindex == 1:
        s = m.group(0)
        g = m.group(1)
        idx = s.find(g)
        if idx != -1:
            return s[:idx] + REDACTED + s[idx + len(g) :]
        return REDACTED
    return REDACTED


def contains_secret(text: str) -> bool:
    if not text:
        return False
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            return True
    return False


def redact_list(items: list[str]) -> list[str]:
    return [redact_text(x) for x in items]
