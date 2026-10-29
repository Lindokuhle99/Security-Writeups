# JWT `alg:none` Authentication Bypass — Full Account Impersonation

**Target type:** E-commerce-style web application (image marketplace), private technical assessment — identifying details redacted
**Role:** Independent assessor, written authorization granted
**Tools used:** Burp Suite (Community Edition), OpenVPN, Burp Decoder, Burp's built-in Chromium browser
**Methodology:** Fully manual — no automated scanners. Walked every feature as a normal user first, then went back over each one systematically: authorization boundaries, mass assignment, business logic limits, injection points, HTTP-level behavior (methods, headers, CORS).

> This write-up is based on a private technical assessment I completed as part of an application process. The target name, flag values, real usernames/emails, and other identifying details have been redacted or replaced, since the environment and its contents were confidential. The vulnerability classes, methodology, and remediation below are unchanged and reflect the actual work.

## Summary

I found six vulnerabilities in a web application assessment, ranging from Critical to Low-Medium. The most serious was a **JWT `alg:none` authentication bypass** — the server accepted completely unsigned tokens and trusted whatever identity claims were written inside them. This meant anyone, with no account or password, could forge a token for any user ID, including the platform administrator, and be treated as that user — both for reading private data and for writing (posting content under someone else's identity).

Alongside that, I found a DOM-based open redirect reachable without authentication, two independent stored XSS bugs, a CORS misconfiguration, and missing rate-limiting on the admin login endpoint.

I also spent significant time on things that *didn't* work — mass assignment, price tampering, voucher abuse, SQL injection, several IDOR attempts, HTTP method tampering — documented below, since confirmed negatives show the coverage was thorough rather than lucky.

## Finding 1: JWT `alg:none` Authentication Bypass (Critical)

**Risk rating:** Critical

### Description

The application issues HS256-signed JWTs for authentication, sent as `Authorization: Bearer <token>`. The problem: endpoints validating this token (profile lookup, order history, comment posting, etc.) would also accept a token that wasn't signed at all. If the JWT header declared `{"alg":"none","typ":"JWT"}` with an empty signature segment, the server simply decoded the payload and trusted the claims inside — without ever checking the token was actually issued by the server.

Since the attacker fully controls the payload of an unsigned token, they can set the user-ID claim to *any* value and the app will treat them as that user. No credentials, no password, no prior access required.

Root cause: the JWT verification logic didn't pin down which signing algorithm was acceptable, and didn't explicitly reject `alg:none`. This is a well-documented class of JWT implementation mistake — treating "decode" as equivalent to "verify," when they are not the same operation.

### Steps to Reproduce

1. Log in normally and note your own user ID from the profile/auth endpoint.
2. In Burp Decoder, base64url-encode (no padding) the header `{"alg":"none","typ":"JWT"}`, then separately encode a forged payload such as `{"sub":"1","username":"<admin-account>","is_admin":true}`.
3. Join them as `<encoded_header>.<encoded_payload>.` — keep the trailing dot and empty third segment where the signature would normally go.
4. In Burp Repeater, swap the `Authorization: Bearer <token>` value on any authenticated request for this forged token.
5. Send it — the server responds `200 OK` with the **full account object of the target user ID**, including role/admin flags.
6. Repeating with a different forged user ID returned another real user's private data (email, balance, tax ID, etc.).
7. To confirm this wasn't just a read bug, I sent a write request (posting a comment) using a forged token for a different user. The server returned `201 Created`, with the comment correctly attributed to the impersonated user — a real write happened under someone else's identity using nothing but a self-typed token.
8. As a boundary check, I tried the same technique against separate admin-only endpoints (which used a different, cookie-based auth mechanism) and got a clean rejection — confirming the flaw was scoped to the main user-auth JWT path, not system-wide.

### Business Impact

Anyone, with no account at all, can read and write data as any user on the platform, including the administrator. Demonstrated impact included exposure of private account data (email, balance, sensitive identifiers) and unauthorized content creation under another identity. Combined with the stored XSS or CORS findings below, the practical reach grows further — though neither of those requires this bug to function on its own.

### Remediation

- Explicitly allow-list acceptable signing algorithms in the JWT verification config (e.g., HS256 only), and reject any token whose header doesn't match.
- Never let verification logic branch based on the token's own claimed `alg` value.
- Use a current, patched JWT library configured to require signature verification unconditionally, with no opt-out.
- Add automated tests that specifically try `alg:none` and algorithm-confusion tokens against every authenticated endpoint, so this can't silently regress.

---

## Finding 2: DOM-Based Open Redirect (Unauthenticated) (High)

**Risk rating:** High

### Description

The logout flow read a `next` value straight from the page's query string and passed it to a redirect endpoint. The server reflected that value back with **no validation of any kind** — no allow-list, no scheme check. The frontend then executed `window.location.href = redirect_to`, sending the browser wherever that value pointed. Because the sink is client-side JavaScript acting on server-supplied data (rather than a server `Location:` header), this is specifically a **DOM-based** open redirect — meaning the fix needs to happen in both the backend (validate input) and the frontend (don't blindly trust what comes back).

No authentication was required to reach this endpoint, making it exploitable against any visitor who clicks a crafted link — not just existing account holders.

### Steps to Reproduce

1. Request the redirect endpoint with `?next=http://attacker-controlled-domain.example` — no `Authorization` header required.
2. The server reflects the value back unmodified in the response, confirming no validation.
3. Retested with a `javascript:` scheme payload in place of a URL — also reflected unmodified, confirming there's no scheme restriction at all, not just a missing host allow-list.
4. Repeating without any session/auth header still succeeded identically, confirming the endpoint requires no authentication.

### Business Impact

An attacker can build a link to the legitimate domain that silently redirects any visitor to a phishing page, without needing them to be logged in. Because the initial URL is the real domain, this is a stronger phishing vector than a plain external link — it looks trustworthy right up until the redirect fires.

### Remediation

- Validate the redirect target server-side against a strict allow-list of known-internal paths.
- If external redirects are never actually needed, restrict the parameter to relative, in-app paths only.
- Don't act on a server-supplied redirect target client-side without validating it there too — defense in depth.

---

## Findings 3 & 4: Stored XSS in Two Independent Features (High)

**Risk rating:** High (each)

### Description

Two separate user-generated-content features — comments and reviews — failed to encode or sanitize submitted content before rendering it back to other users. Submitted HTML/JS ran in the browser of anyone who later viewed the content. Because the application stored its JWT in `localStorage` rather than an `HttpOnly` cookie, either of these was directly usable to steal another logged-in user's session token.

Finding the same gap independently in two unrelated features (different endpoints, different code paths) pointed to a systemic output-encoding issue rather than a single missed spot.

### Steps to Reproduce

1. Submit an image-tag XSS payload (`<img src=x onerror="...">`) as a comment or review body.
2. View the same content from a different account.
3. The payload executes immediately on page load — confirmed by reading the second account's own session token directly out of its `localStorage` via the injected script.

### Business Impact

An attacker can run arbitrary JavaScript in the browser of anyone who views the poisoned content, with no interaction beyond loading the page. Combined with session tokens sitting in `localStorage`, this is a full session-hijacking primitive — an attacker could silently exfiltrate a viewer's token and impersonate them completely.

### Remediation

- HTML-encode all user-supplied content before rendering, or run it through an allow-list sanitizer.
- If using React or a similar framework, ensure content goes through standard interpolation (which auto-escapes) rather than any "raw HTML" injection method.
- Move session tokens out of `localStorage` into an `HttpOnly`, `Secure` cookie, so that even successful XSS can't read the token directly.
- Fix at the shared rendering/output-encoding layer rather than per-feature, since the same gap had already appeared twice independently.

---

## Finding 5: CORS Misconfiguration — Arbitrary Origin Reflection (Low-Medium)

**Risk rating:** Low-Medium

### Description

Several API endpoints reflected whatever value was sent in the client's `Origin` header straight back in `Access-Control-Allow-Origin`, instead of checking it against a list of legitimate origins.

This was deliberately rated lower rather than Critical: the response never included `Access-Control-Allow-Credentials: true`, and the app authenticated via a `Bearer` token in the `Authorization` header rather than a cookie — so a malicious site couldn't automatically make a victim's browser attach their token to a forged cross-origin request. An attacker would need the token through some other means first, making this a compounding issue rather than a primary entry point.

### Business Impact

Low on its own given the bearer-token model, but shows a real lack of origin validation that could become more serious if the authentication mechanism ever changed (e.g., a future move to cookie-based sessions), or if chained with the XSS findings above (which already give a malicious page access to a token).

### Remediation

Implement a strict server-side allow-list of legitimate origins, and only set `Access-Control-Allow-Origin` when the incoming `Origin` actually matches.

---

## Finding 6: Missing Rate-Limiting on Admin Login (Medium)

**Risk rating:** Medium

### Description

The admin login endpoint had no account lockout or rate-limiting after repeated failed attempts. Six consecutive incorrect-password attempts against the same account all returned an identical `401`, with no escalating delay, no `429`, and no lockout. To its credit, the error message didn't distinguish "account doesn't exist" from "wrong password" (good anti-enumeration practice), but that doesn't offset the missing throttling.

### Business Impact

Given more time, better tooling, or a larger wordlist, an attacker could realistically brute-force weak admin credentials with zero pushback and zero alerting.

### Remediation

Add account lockout after a set number of failed attempts (five is a reasonable starting point), paired with IP-based rate-limiting and alerting on repeated failures against the same account.

---

## Confirmed Negatives (What Held Up)

Worth documenting what I tried that *didn't* work, since it shows the coverage was systematic:

- **Mass assignment** on profile and seller-application endpoints — both correctly whitelist accepted fields; injecting privilege-related fields had no effect.
- **Voucher amount tampering** — negative, zero, decimal, and out-of-range amounts correctly rejected with `400`.
- **Voucher reuse** — correctly blocked with `409` on double-redemption.
- **Order IDOR** — no single-order-by-ID endpoint existed to attack.
- **Purchase price tampering** — server calculated and enforced price itself; client-supplied price overrides were ignored.
- **Review purchase-gating** — correctly enforced; reviewing unpurchased content returned `403`.
- **Review rating bounds** — out-of-range ratings correctly rejected.
- **Comment author spoofing** — server always derived the real author from the authenticated identity, ignoring any client-supplied username field.
- **Daily action-limit bypass** (e.g., upvotes) — enforced server-side, not just hidden in the frontend.
- **Classic SQL injection** — tested against search and login forms; properly parameterized, no anomalies.
- **HTTP method tampering** — swapping `POST` for `PUT` on sensitive endpoints correctly returned `405`.
- **Path traversal** on a file-download endpoint — rejected at the web server layer before reaching the application.
- **Admin-endpoint access via a regular user's valid token** — correctly rejected; the separate admin auth system did not share the `alg:none` weakness found in the main user-auth path.
- **Admin credential guessing** — a small number of plausible weak/default passwords tried against the real admin account; none succeeded.

## Takeaways

The JWT `alg:none` bypass is the standout lesson here: "decode" and "verify" are not the same operation, and any JWT library configuration that doesn't hard-pin acceptable algorithms is one misconfiguration away from a full authentication bypass. The two independent stored XSS findings reinforced that output encoding needs to be handled centrally, not per-feature — the same gap appearing twice in unrelated code paths is a signal, not a coincidence. Documenting the confirmed negatives alongside the real findings was also valuable practice: it forces rigor (ruling out other explanations before writing something up) and gives a fuller, more honest picture of an assessment than a highlight reel of wins would.
