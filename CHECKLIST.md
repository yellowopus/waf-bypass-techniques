# WAF Evasion Testing Checklist

Copy-paste checklist for an authorized WAF evasion test. Work top to bottom, check each item off, and record the result of every test — including the ones that failed.

> **Scope reminder:** only test targets you own or have explicit written authorization for. All examples use `example.com` as a generic placeholder.

## 0. Before You Start

- [ ] Written authorization confirmed, scope and in-scope endpoints listed
- [ ] Test account(s) created; no production user data involved
- [ ] Isolated environment preferred for smuggling / state-changing tests
- [ ] Baseline benign request sent and recorded (status, headers, body size, timing)
- [ ] Plain malicious payload sent and block response recorded (status, block page, headers)
- [ ] Rate limiting distinguished from WAF blocking (429 ≠ 403)
- [ ] Caching checked — responses confirmed fresh (cache-busting parameter used)

## 1. Encoding Evasion

- [ ] URL encoding (full)
- [ ] URL encoding (partial — encode only some characters)
- [ ] Double URL encoding (`%253C`)
- [ ] Mixed case keywords (`SeLeCt`, `uNiOn`)
- [ ] Comment insertion (`SEL/**/ECT`)
- [ ] Whitespace alternatives (tab, newline, carriage return, vertical tab, form feed)
- [ ] Hex literals (`0x756E696F6E`)
- [ ] Octal escapes (`\74script\76`)
- [ ] HTML entities — decimal (`&#60;`) and hex (`&#x3c;`)
- [ ] Unicode / overlong UTF-8 (`%u003C`, `%C0%BC`) — legacy stacks only
- [ ] Null byte (`%00`) — legacy stacks only
- [ ] For each success: verified the application actually decoded and interpreted the payload

## 2. HTTP-Layer Evasion

- [ ] Content-Type switch: form → JSON
- [ ] Content-Type switch: form → multipart/form-data
- [ ] Content-Type switch: form → XML
- [ ] Chunked transfer encoding to fragment the payload
- [ ] Multipart boundary abuse (long/special-character/missing final boundary)
- [ ] Parameter pollution: benign first, payload second (`?q=safe&q=<payload>`)
- [ ] Parameter pollution: reversed order (`?q=<payload>&q=safe`)
- [ ] Parameter pollution in POST body (form and multipart)
- [ ] Array-style keys (`?id[]=1&id[]=2`)
- [ ] Nested / bracket keys (`?user[role]=user&user[role]=admin`)
- [ ] Duplicate keys in JSON body
- [ ] Client-IP header spoofing (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `True-Client-IP`)
- [ ] Absolute-URI request line (`GET http://example.com/path?...`)
- [ ] Path normalization (`/./admin`, `//admin`, `/%61dmin`, `/admin;jsessionid=x`)
- [ ] Alternate HTTP method (POST → PUT / PATCH)
- [ ] Request-line / header case variations

## 3. HTTP/2 Checks (only if the target supports HTTP/2)

- [ ] HTTP/2 support confirmed
- [ ] h2c upgrade probe (`Upgrade: h2c` → `101 Switching Protocols`?)
- [ ] Pseudo-header path discrepancy (`:path: /public/../admin`)
- [ ] Duplicate `:path` pseudo-headers
- [ ] `:authority` vs `Host` disagreement
- [ ] `:scheme` manipulation
- [ ] H2 → H1 downgrade: CRLF inside a header value
- [ ] H2 → H1 downgrade: `Transfer-Encoding` passthrough
- [ ] H2 → H1 downgrade: conflicting `Content-Length`

## 4. Request Smuggling (isolated environment only)

- [ ] Two-hop path confirmed (proxy/CDN in front of origin)
- [ ] CL.TE probe sent
- [ ] TE.CL probe sent (chunk lengths recalculated exactly)
- [ ] TE.TE obfuscation variants tested one at a time
- [ ] H2.CL / H2.TE variants tested (if HTTP/2 in path)
- [ ] Desync confirmed with a replay-safe second request
- [ ] No shared pool or cache poisoned; no other user's traffic affected

## 5. Verification (for every claimed bypass)

- [ ] Payload confirmed to have reached the application (not silently stripped)
- [ ] Payload confirmed interpreted as intended by the application
- [ ] Result reproduced on a fresh connection with a cache-busted request
- [ ] Benign baseline re-run and confirmed to behave differently
- [ ] Only one variable changed from the blocked baseline request
- [ ] Impact scoped honestly: real exploitability vs. WAF observation

## 6. Reporting

- [ ] Target endpoint, parameter, and context documented
- [ ] Baseline block response recorded
- [ ] Exact raw bypass request saved (minimal diff from baseline)
- [ ] Evidence of payload reaching the sink attached
- [ ] Root cause identified (which parsing/decoding disagreement)
- [ ] Impact stated for this application, not in theory
- [ ] Remediation recommended at the application layer first, WAF rule as stopgap
- [ ] All test artifacts and notes retained for the report
