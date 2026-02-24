# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability in BlazeHTTP, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Open a [private security advisory](https://github.com/justIliane/blazehttp/security/advisories/new) on GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Known Mitigations

BlazeHTTP includes protections against common HTTP/2 attacks:

- **CVE-2023-44487 (Rapid Reset)** — Detected and mitigated with GOAWAY ENHANCE_YOUR_CALM
- **PING flood** — Rate-limited to 1000 control frames per 10-second window
- **SETTINGS flood** — Rate-limited to 1000 control frames per 10-second window
- **RST_STREAM flood** — Counted in the control frame rate limiter
- **HPACK bomb** — Dynamic table size strictly enforced per SETTINGS_HEADER_TABLE_SIZE
- **Integer overflow** — Bounds checking on all HPACK integer decoding
- **Flow control exhaustion** — Send window blocking with timeout prevents starvation

## Fuzzing

BlazeHTTP has been fuzzed with 1.36 billion total executions across three parsers:

- HTTP/1.1 header parser: 308 million executions
- HPACK decoder: 539 million executions
- HTTP/2 frame reader: 518 million executions

One bug was found (HPACK integer overflow in `decodeString`) and fixed with a regression test.
