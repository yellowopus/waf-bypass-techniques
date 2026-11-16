# Encoding Evasion

How different encodings of the same payload can slip past a WAF that matches on literal strings — and how to test each one systematically.

> **Scope reminder:** only test targets you own or have explicit written authorization for. All examples use `example.com` as a generic placeholder.

## Why Encoding Works

A WAF usually inspects the request as it arrives on the wire. The application, however, may decode the input one or more times before using it. If the WAF and the application decode differently, a payload that looks harmless to the WAF can become dangerous after the application decodes it.

```
WAF sees:      %253Cscript%253E   → looks like harmless text, allowed
App decodes:   %3Cscript%3E       → then decodes again → <script>
```

The rule of thumb: **test every encoding the application might apply, and check whether the WAF applies the same decoding.**

## 1. URL Encoding

Percent-encode characters the WAF matches on literally.

| Original | URL-encoded |
|---|---|
| `<script>` | `%3Cscript%3E` |
| `SELECT` | `%53ELECT` (partial encoding also works: encode only some letters) |
| space | `%20`, `+` |

Partial encoding is often more effective than encoding everything — encode just enough characters to break the WAF's pattern while keeping the payload valid for the application.

## 2. Double URL Encoding

Encode the `%` sign itself (`%` → `%25`), so the payload is encoded twice.

| Original | Double-encoded |
|---|---|
| `<` | `%253C` |
| `>` | `%253E` |
| `/` | `%252F` |

This works when the WAF decodes once and the application decodes twice. If the application only decodes once, the payload arrives still-encoded and is harmless — verify the result, don't assume.

## 3. Unicode and Overlong UTF-8 Encoding

Some parsers normalize non-ASCII or overlong UTF-8 sequences into ASCII characters; a WAF that does not perform the same normalization misses them.

- **Unicode escapes:** `%u003C` for `<` (mainly legacy servers that perform this normalization).
- **Overlong UTF-8:** `%C0%BC` is an overlong (technically invalid) encoding of `<`. Strict parsers reject it; loose parsers accept it and normalize it to `<`.
- **UTF-16 / UTF-7 style encodings:** relevant only where the application explicitly decodes them; test, don't assume.

Modern stacks mostly reject overlong UTF-8, so treat this as a legacy-parser check, not a first-line technique.

## 4. Case Variation

If WAF rules match keywords case-sensitively, mixed case breaks the match while many interpreters accept it.

```
SeLeCt * FrOm users
uNiOn SeLeCt 1,2,3
<ScRiPt>alert(1)</ScRiPt>
```

Test both directions: some WAFs normalize case and some applications are case-sensitive, so a mixed-case payload may fail at the application even if it passes the WAF.

## 5. Comment Tricks

Insert comments inside keywords so the WAF's literal pattern no longer matches, while the target interpreter ignores the comment.

```sql
SEL/**/ECT * FR/**/OM users
UN/**/ION SEL/**/ECT 1,2,3
```

Variants to try:

- `/**/` (SQL-style inline comment)
- `/* comment */` with content inside
- `--` line comments where the syntax allows
- Nested or repeated comments: `/****/`

## 6. Whitespace Alternatives

Keywords are usually separated by spaces, but many interpreters accept other whitespace or separators. If the WAF pattern expects a literal space, an alternative separator breaks it.

```sql
SELECT	*	FROM	users        -- tab characters
SELECT
*
FROM
users                            -- newline as separator
SELECT/**/ * /**/FROM users     -- comment as separator (see §5)
```

Try, in order: space, tab (`%09`), newline (`%0A`), carriage return (`%0D`), vertical tab (`%0B`), form feed (`%0C`).

## 7. Null Bytes and Truncation

A null byte (`%00`) can make some parsers stop reading a value early.

```
sel%00ect
```

Effect depends entirely on the stack: some parsers truncate at the null byte, some reject the request, some pass it through unchanged. This is a legacy technique — verify behavior on the target stack before relying on it.

## 8. Hex and Octal Literals

Represent strings as numbers so no literal keyword appears in the request at all.

```sql
-- Hex literal for the string 'union' (SQL)
0x756E696F6E

-- Octal escapes, where the parser supports them
\74script\76
```

This is most useful for SQL keywords: the database converts the hex literal back to a string, while a WAF matching the word `union` sees only digits.

## 9. HTML Entities (XSS Context)

When the payload lands in an HTML context, entities can hide it from a WAF that doesn't decode them.

```html
&#60;script&#62;          <!-- decimal entities -->
&#x3c;script&#x3e;        <!-- hex entities -->
```

The browser decodes entities before parsing HTML, so the payload executes if the application reflects it without encoding. Verify in the actual rendering context — entity decoding behavior varies by insertion point.

## Testing Order

Work through encodings from simplest to most exotic, one variable at a time:

1. Plain payload (baseline — confirm it is blocked, and how).
2. URL encoding, then partial URL encoding.
3. Double URL encoding.
4. Mixed case.
5. Comments and whitespace alternatives.
6. Hex/octal literals.
7. Unicode / overlong UTF-8 (legacy stacks only).
8. Null byte (legacy stacks only).

Record which encoding the WAF missed **and** whether the application still interpreted the payload — a bypass that the application doesn't decode is not a finding.
