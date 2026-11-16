# HTTP-Layer Evasion

Techniques that exploit how different layers of a request path — proxy, WAF, application server, framework — parse the same HTTP request differently. These are protocol tricks, not payload tricks: the payload may be unchanged, but the way it is framed makes the WAF see something different from what the application sees.

> **Scope reminder:** only test targets you own or have explicit written authorization for. All examples use `example.com` as a generic placeholder. Request smuggling tests can poison shared connection pools and affect other users — prefer an isolated environment.

## 1. HTTP/2-Specific Behaviors

HTTP/2 transmits requests as binary frames with HPACK-compressed headers, not as plain-text lines. A WAF that only understands HTTP/1.1 may inspect a downgraded copy of the request — and the downgrade itself can introduce gaps.

### 1.1 h2c Upgrade Smuggling

`h2c` is HTTP/2 without TLS, negotiated through an HTTP/1.1 `Upgrade` request. A reverse proxy that forwards the `Upgrade: h2c` header without understanding it can become a blind TCP tunnel: the client then speaks HTTP/2 directly to the backend, and the proxy-side WAF never sees the real requests.

```http
GET / HTTP/1.1
Host: example.com
Upgrade: h2c
HTTP2-Settings: <base64-encoded HTTP/2 settings>
Connection: Upgrade, HTTP2-Settings
```

A `101 Switching Protocols` response means the upgrade succeeded. What this can bypass, in principle: path-based access controls, proxy-side WAF rules, proxy-level rate limits, and proxy-enforced authentication — all because the proxy can no longer inspect the traffic.

### 1.2 Pseudo-Header Confusion

HTTP/2 replaces the request line with pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`). If the proxy and the backend parse them differently, routing and access control disagree:

| Mismatch | Effect |
|---|---|
| `:path: /public/../admin` | Proxy routes on `/public/*` (allowed); backend normalizes to `/admin` |
| Duplicate `:path` headers | Proxy uses the first, backend uses the last (or vice versa) |
| `:authority` vs `Host` header | Proxy routes by `:authority`; backend serves a different virtual host based on `Host` |
| `:scheme` manipulation | Backend trusts `:scheme` to decide whether a request is "internal" |

The HTTP/2 spec forbids duplicate pseudo-headers, but implementations vary — that variance is the attack surface.

### 1.3 HTTP/2 → HTTP/1.1 Downgrade Issues

When a proxy translates HTTP/2 to HTTP/1.1 for the backend, translation flaws appear:

- **Header injection via binary values:** a header value in HTTP/2 is binary data, so it can legally contain `\r\n`. During downgrade, those bytes can become a real line break in HTTP/1.1, injecting a new header.
- **Transfer-Encoding passthrough:** HTTP/2 forbids `transfer-encoding`, but a proxy may forward it during downgrade, letting the backend parse a chunked body the proxy never saw (see §3).
- **Content-Length discrepancy:** HTTP/2 uses frame lengths and needs no `Content-Length`. If the proxy generates one during downgrade while the client also sent one, the two lengths can conflict — another smuggling primitive.
- **Header-name case:** HTTP/2 requires lowercase header names. An uppercase `Transfer-Encoding` is invalid HTTP/2, but some proxies pass it through as a valid HTTP/1.1 header on the backend.

### 1.4 Multiplexing and Stream Abuse

HTTP/2 multiplexes many streams over one connection. Two consequences worth knowing:

- **Single-packet race conditions:** multiple requests packed into one TCP segment arrive effectively simultaneously, enabling true race-condition testing.
- **Rapid Reset (CVE-2023-44487):** opening a stream with `HEADERS` and immediately cancelling it with `RST_STREAM`, repeated thousands of times per second, exhausts server CPU with minimal client resources. This is a denial-of-service vector — never test it against production, and treat it as a resilience finding, not a bypass.

## 2. HTTP Parameter Pollution (HPP)

HTTP does not forbid sending the same parameter name twice (`?a=1&a=2`). Each layer in the request path may pick a different occurrence — first, last, joined, or as an array. When the WAF and the application disagree, the WAF inspects a benign value while the application acts on a malicious one.

### 2.1 How Different Stacks Parse Duplicates

| Technology | Behavior for `?a=1&a=2` |
|---|---|
| PHP / Apache | Last value: `a=2` |
| ASP.NET / IIS | Often comma-joined: `a=1,2` |
| JSP / Tomcat | First value: `a=1` |
| Python / Django | Last value: `a=2` |
| Python / Flask | First value: `a=1` |
| Node.js / Express | Array: `a=['1','2']` |
| Ruby / Rack | Last value: `a=2` |
| Go `net/http` | First value: `a=1` |

These are typical defaults — middleware and custom parsers override them. **Always confirm empirically** on the target stack before building an attack on an assumption.

### 2.2 The WAF-Bypass Pattern

```
GET /search?q=safe&q=<payload> HTTP/1.1
```

If the WAF inspects the first value (`safe`) and the application uses the last (`<payload>`), the payload passes. Test both orders (`a=1&a=2` and `a=2&a=1`) — some parsers are order-sensitive.

### 2.3 Variations to Test

- **Duplicate keys in the query string:** `?id=1&id=2`
- **Duplicate keys in the POST body:** same name twice in `application/x-www-form-urlencoded` or `multipart/form-data`
- **Array-style keys:** `?id[]=1&id[]=2` (PHP and some frameworks)
- **Mixed array and scalar:** `?item[]=a&item=b`
- **Encoded ampersand:** `param=value1%26other=value2` — one parser may treat `%26` as a literal `&` inside a value, another as a parameter separator
- **Nested / bracket keys:** `?user[role]=user&user[role]=admin`
- **Duplicate keys in JSON:** `{"role":"user","role":"admin"}` — most parsers keep the last key; some keep the first

### 2.4 Beyond WAF Bypass

The same disagreement enables other issues wherever two components read the same parameter:

- **SSRF split:** a validator reads the safe URL, the fetcher reads the second URL.
- **CSRF token confusion:** one copy satisfies one parser, another copy satisfies the other.
- **Business-logic abuse:** `amount=1&amount=5000` — the price check sees one value, the charge uses the other.

HPP testing can change server state (payments, account settings). Run it only where explicitly authorized, with scoped test accounts, and document parser behavior before sending high-impact requests.

## 3. Request Smuggling Concepts

Request smuggling is a **message-boundary disagreement**: two HTTP processors on the same connection disagree about where one request ends and the next begins, so a smuggled second request hides inside the first.

```
Client → Front (proxy/WAF) → Back (origin)
         parses boundary #1    parses boundary #2
         (sees Request A)      (sees Request A' + smuggled Request B)
```

Impact: the smuggled request bypasses the WAF entirely (the front end never saw it as a request), can poison shared connection queues so it executes in another user's session, and can assist cache poisoning.

### 3.1 CL.TE — Front Trusts Content-Length, Back Trusts Chunked

Both `Content-Length` and `Transfer-Encoding: chunked` are present. The front end reads only `Content-Length` bytes and considers the request complete; the back end parses chunked encoding and treats the leftover bytes as the start of a new request.

```http
POST / HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front end reads 13 bytes (`0\r\n\r\nSMUGGLED`) and stops. The back end sees the `0` end-chunk, then treats `SMUGGLED` as the beginning of the next request.

### 3.2 TE.CL — Front Trusts Chunked, Back Trusts Content-Length

The front end parses the whole chunked body; the back end reads only `Content-Length` bytes, leaving the rest buffered to splice onto a later request.

```http
POST / HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: example.com
Foo: x

0


```

The back end reads 4 bytes (`35\r\n`) and considers the body complete. The remaining bytes — including the embedded `GET /admin` request — stay in the buffer and are parsed as the next request. **Chunk lengths are exact hex byte counts**: if you change the embedded request, recalculate the chunk size.

### 3.3 TE.TE — Obfuscated Transfer-Encoding

Both hops claim to process `Transfer-Encoding`, but differ on which value or spelling counts as `chunked`. Probe with obfuscation variants, one at a time, and map which hop accepts each:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before the colon)
Transfer-Encoding: chunked           (sent twice)
Transfer-Encoding: x
Transfer-Encoding:<TAB>chunked
 Transfer-Encoding: chunked          (leading space)
Transfer-Encoding<newline>: chunked  (field name and colon on separate lines)
```

For each variant, determine whether the front end, the back end, both, or neither treat it as chunked — then map the result back to a CL.TE or TE.CL case.

### 3.4 HTTP/2 Smuggling Variants

- **H2.CL / H2.TE:** the same length-vs-chunked disagreement, reached through HTTP/2 → HTTP/1.1 downgrade (see §1.3).
- **CL.0:** a `Content-Length: 0` mismatch that desynchronizes the connection on close.
- **Fat GET:** a body smuggled inside a GET request, which some stacks accept and others ignore.

### 3.5 Confirming a Desync Safely

A smuggling finding is only real if a second request can actually be smuggled and observed. Confirm with a replay-safe probe (for example, a harmless request to a distinct path whose response you can distinguish), or with an out-of-band side signal. Never confirm by poisoning a shared pool with requests that could execute in another user's session — use an isolated environment or a dedicated test connection.

## 4. Header Tricks

### 4.1 Client-IP Headers

Some WAFs and applications trust headers to determine the client IP, and apply different rule sets to "internal" addresses:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

If a WAF whitelists internal IPs or relaxes rules for them, spoofing one of these headers can change which rules apply. Only meaningful where the stack actually trusts the header — verify, don't assume.

### 4.2 Content-Type Manipulation

WAFs often have format-specific parsers. Switching `Content-Type` can move the payload into a format the WAF inspects weakly or not at all:

| Sent as | WAF behavior |
|---|---|
| `application/x-www-form-urlencoded` | Parses parameters (strong inspection) |
| `application/json` | May not parse the JSON body deeply |
| `multipart/form-data` | May not inspect all parts, especially file content |
| `text/xml` | Expects XML; payload in another format may pass unexamined |

If the application accepts both form data and JSON for the same endpoint, sending the payload as JSON is a common bypass — but only if the application actually parses it that way. Verify the payload still reaches the sink.

### 4.3 Multipart Boundary Abuse

```http
Content-Type: multipart/form-data; boundary=----TestBoundary

------TestBoundary
Content-Disposition: form-data; name="q"

<payload here>
------TestBoundary--
```

Variations: unusually long boundary strings, boundaries with special characters, a missing final boundary, nested multipart sections. Some WAFs fail to parse the parts at all and skip inspection.

### 4.4 Chunked Transfer Encoding (Fragmentation)

Split the payload across HTTP chunks so no single chunk contains the blocked pattern:

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

3
sel
3
ect
0

```

A WAF that inspects chunks individually instead of reassembling the full body will not see `select`. Whether this works depends on whether the WAF reassembles before matching.

### 4.5 Request-Line and Path Tricks

- **Absolute URI:** `GET http://example.com/path?q=<payload> HTTP/1.1` — some WAFs inspect only the origin-form path and miss the absolute form.
- **Dot segments:** `/./admin`, `/../target/admin` — the WAF and the application may normalize the path differently.
- **Double slash:** `//admin` — some normalizers collapse it, others don't.
- **Encoded path segments:** `/%61dmin` — the WAF sees encoded text, the application decodes it.
- **Semicolon parameters:** `/admin;jsessionid=x` — some servers strip everything after `;`, the WAF may not.
- **Trailing dot or space:** `/admin.` or `/admin%20` — operating-system-level normalization (mainly Windows stacks).
- **Backslash:** `/admin\..\secret` — some servers treat `\` as `/`.
- **Different HTTP method:** the same functionality may be reachable via `PUT` or `PATCH` with weaker WAF rules than `POST`.

## 5. Defense Perspective

These techniques all exploit the same root cause: **two parsers disagreeing**. The durable fixes are on the defense side:

- Normalize, decode, and canonicalize input **once, at the edge**, and pass the canonical form downstream — never let each hop decode independently.
- Reject requests with ambiguous framing (both `Content-Length` and `Transfer-Encoding`, duplicate `Content-Length`, obfuscated `Transfer-Encoding`) instead of guessing.
- Prefer allowlist validation of input shape over blocklist keyword matching.
- Keep the WAF as one layer among several: application-level validation, parameterized queries, and output encoding are what actually stop the attack.
- Log and alert on WAF blocks and on malformed framing — bypass attempts are usually visible in logs before they succeed.
