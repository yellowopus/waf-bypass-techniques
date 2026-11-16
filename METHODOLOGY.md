# Methodology

A repeatable workflow for WAF evasion testing. The goal is not to "get past the WAF" — it is to determine, with evidence, whether the WAF actually protects the application, and to report exactly which gap (if any) exists.

> **Scope reminder:** only test targets you own or have explicit written authorization for. Stay in scope, use test accounts, and prefer an isolated environment for anything that can affect shared state.

## Phase 0 — Baseline Detection

Before testing any bypass, establish what you are dealing with.

1. **Send a benign request** and record the baseline: status code, response headers, body size, and response time.
2. **Send an obviously malicious request** (for example, a plain `<script>` tag or `UNION SELECT` in a parameter) and compare: 403? A custom block page? A redirect? A connection reset? A 200 with the payload silently stripped?
3. **Identify the layer doing the blocking.** Response headers and block-page wording can hint at a WAF, but the decisive question is behavioral: does the block happen before the application sees the request, or does the application itself reject it?
4. **Distinguish the WAF from rate limiting.** Repeated 429 responses are rate limiting, not payload blocking — different problem, different response.
5. **Check for caching.** If a CDN sits in front, a cached response can mask what the WAF actually does. Use cache-busting parameters and confirm responses are fresh.

Record the baseline in writing. Every later result is judged against it.

## Phase 1 — Minimal Benign Probe

Before any attack payload, confirm you understand the endpoint's normal behavior.

1. Send a **minimal, benign value** for the parameter you intend to test (for example, a plain word or number).
2. Confirm it is reflected or processed as expected, and note exactly where it appears in the response (reflected in HTML, stored, used in a query, logged, etc.).
3. Note the parameter's context: query string, form body, JSON field, header, cookie, or path segment. The context decides which techniques apply.
4. Confirm the parameter actually reaches a sink (a query, a template, a command). A parameter that is accepted but never used cannot be exploited, whatever the WAF does.

## Phase 2 — Single-Variable Evasion Tests

Test one change at a time. If you change encoding, content type, and parameter order simultaneously, you will not know which change worked — and you will not be able to reproduce or report the finding.

### Step 1 — Encoding (see ENCODING.md)

Work simplest to most exotic:

1. Plain payload (confirm it is blocked, and record the exact block response).
2. URL encoding, then partial URL encoding.
3. Double URL encoding.
4. Mixed case.
5. Comment insertion and whitespace alternatives.
6. Hex / octal literals.
7. Unicode / overlong UTF-8 and null byte (legacy stacks only).

### Step 2 — HTTP-layer tricks (see HTTP-TRICKS.md)

1. Content-Type switch (form → JSON → multipart → XML), only where the application accepts the alternate format.
2. Chunked transfer encoding to fragment the payload.
3. Parameter pollution: duplicate the parameter with a benign first value and the payload second, then reverse the order.
4. Path normalization variants for path-based rules.
5. Header tricks: client-IP headers, absolute-URI request line, alternate HTTP method.
6. HTTP/2 behaviors, only if the target supports HTTP/2: h2c upgrade probe, pseudo-header discrepancies, downgrade artifacts.

### Step 3 — Payload mutation

If the payload class itself has alternatives, try them — but keep the framing constant while you do:

- SQL: alternative keywords and functions, different boolean expressions.
- XSS: alternative tags and event handlers, template literals.
- Command execution: string concatenation, variable expansion, wildcard abuse.

### Step 4 — Request smuggling (only in an isolated environment)

Only after the simpler techniques are exhausted, and only where the impact is contained:

1. Confirm a two-hop path (proxy/CDN in front of an origin) exists.
2. Probe CL.TE, then TE.CL, then TE.TE obfuscation variants — one at a time.
3. Confirm with a replay-safe second request, never by poisoning a shared pool.

## Phase 3 — Verify the Bypass

A bypass is not proven by a 200 response. Verify each of these:

1. **The payload reached the application.** The WAF may have returned 200 while silently stripping the payload. Check server-side logs, or use a payload with an observable, harmless effect (for example, a distinctive marker reflected in the response).
2. **The payload was interpreted as intended.** An encoded payload that arrives still-encoded is not a bypass — the application must decode it into the dangerous form.
3. **The effect is reproducible.** Send the same request again (fresh connection, cache-busted) and confirm the same result.
4. **The effect is caused by your payload, not by a side effect.** Re-run the benign baseline and confirm it behaves differently.
5. **Scope the impact honestly.** A bypass that only works with a payload the application never executes is a WAF observation, not a vulnerability. Say which one it is.

## Phase 4 — Report

A good WAF-bypass report lets someone else reproduce the finding and fix the root cause. Include:

| Section | Content |
|---|---|
| Target | Endpoint, parameter, and context (query/body/header), in scope |
| Baseline | Block response for the plain payload (status, body excerpt, headers) |
| Bypass | The exact raw request that succeeded (or the minimal diff from the baseline) |
| Evidence | Proof the payload reached the application and was interpreted (response excerpt, log line, observable effect) |
| Root cause | Why it worked: which parsing disagreement, which decoding mismatch, which missing normalization |
| Impact | What an attacker could actually do with this gap, in this application — not in theory |
| Remediation | Fix at the application layer first (validation, parameterized queries, output encoding); WAF rule as a stopgap, with the exact rule suggestion if known |

### Remediation guidance to include

- **Fix the application, not just the rule.** A WAF rule that blocks one encoding leaves the next encoding open. Parameterized queries, allowlist validation, and output encoding close the class of issue.
- **Normalize once, at the edge.** Decode and canonicalize input a single time and pass the canonical form downstream, so no hop can decode differently from another.
- **Reject ambiguous requests.** Requests with both `Content-Length` and `Transfer-Encoding`, duplicate `Content-Length`, or obfuscated framing should be rejected, not guessed at.
- **Prefer allowlists.** Validating that input matches an expected shape is stronger than blocking known-bad strings.

## Common Mistakes

1. **Calling a 200 a bypass.** The WAF may have stripped the payload silently. Always verify the payload reached the sink.
2. **Changing several variables at once.** Unreproducible results and unfixable reports.
3. **Confusing rate limiting with blocking.** 429s mean slow down, not "try a different encoding."
4. **Testing smuggling against production.** Shared connection pools and caches mean your probe can affect other users. Isolate it.
5. **Ignoring request size limits.** Some WAFs skip inspection of very large bodies entirely — a large-body bypass is a finding about inspection limits, and should be reported as one, not treated as a clever encoding.
6. **Forgetting the origin.** If the origin server is reachable directly (bypassing the CDN/WAF), that is a finding in itself — report the exposure, don't just use it.
