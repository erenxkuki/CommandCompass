# Threat model

CommandCompass is a decision-support tool. Threats:
- Malicious command input could attempt to exploit parser (mitigated by no execution, bounds).
- Secret leakage in reports (mitigated by redaction, but best-effort).
- UI injection (mitigated by escaping and CSP).
- DNS rebinding/CSRF to local server (mitigated by loopback bind and headers, but localhost is not a strong boundary).
- Supply-chain risks in dependencies (mitigated by minimal deps).

Out of scope: protecting against a malicious user running dangerous commands themselves.
