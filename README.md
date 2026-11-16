# WAF Bypass Techniques

A practical, focused playbook for testing whether a web application firewall (WAF) can be evaded — and for fixing the gaps it reveals. It distills generic evasion concepts: encoding tricks, HTTP-layer quirks, parameter pollution, and HTTP/2 behaviors, plus a repeatable testing methodology.

## Scope & Authorization

> **Only test targets you own or have explicit written authorization for, and stay strictly in scope.**
>
> - Every example in this repository uses generic placeholders such as `example.com`. Nothing here targets any real third-party site, company, or WAF vendor.
> - Evasion techniques in this playbook are for **authorized security testing only** — penetration tests, bug-bounty programs within their stated scope, and hardening your own systems.
> - Do not use these techniques against systems you do not own or are not authorized to test. Unauthorized access is illegal in most jurisdictions.
> - If a technique could affect other users (shared connection pools, caches, production traffic), use an isolated test environment or a low-traffic window, and stop if you see unexpected side effects.

## Who It's For

- **Penetration testers and bug-bounty hunters** who need to verify whether a WAF actually blocks an attack, or only blocks the obvious form of it.
- **Defenders and developers** who want to understand how WAF rules fail, so they can fix the application itself instead of relying on the WAF alone.
- **Students of web security** learning how HTTP parsing differences create security gaps.

## Contents

| File | What it covers |
|---|---|
| [ENCODING.md](ENCODING.md) | Evasion via encoding: double/Unicode encoding, case variation, comment tricks, whitespace alternatives |
| [HTTP-TRICKS.md](HTTP-TRICKS.md) | HTTP-layer evasion: HTTP/2-specific behaviors, parameter pollution, request smuggling concepts, header tricks |
| [METHODOLOGY.md](METHODOLOGY.md) | Workflow: baseline detection, minimal benign probe, single-variable evasion tests, verification, reporting |
| [CHECKLIST.md](CHECKLIST.md) | Copy-paste checklist for WAF evasion testing |

## The Core Idea

A WAF and the application behind it are two different parsers. The WAF inspects a request one way; the application interprets it another way. Evasion happens in the gap between those two interpretations:

- The WAF decodes a payload once, the application decodes it twice.
- The WAF reads the first value of a duplicated parameter, the application reads the last.
- The WAF sees one request boundary, the application sees two.

Every technique in this playbook is a way of finding and proving one of those gaps — on systems you are authorized to test.

## Key Principles

1. **Identify before you evade.** Know what is blocking you (a WAF, a rate limiter, the application itself) before choosing a bypass. A 403 from a WAF and a 403 from application logic need different responses.
2. **Change one variable at a time.** If you change encoding, content type, and parameter order at once, you will not know which change worked.
3. **A 200 response is not proof.** A WAF may silently strip a payload and return success. Verify that the payload actually reached the application and was interpreted as intended.
4. **The WAF is not the fix.** The durable defense is input validation, parameterized queries, and output encoding in the application. A WAF is a layer, not a cure.

## License

MIT — see [LICENSE](LICENSE).
