# Blind SQL Injection with Conditional Responses

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

The application sets a `TrackingId` cookie used in a backend SQL query for analytics purposes. Unlike the earlier labs, the query's results are never returned or displayed anywhere — this is a **blind** injection. However, the application does behave slightly differently depending on whether the injected condition is true or false: a "Welcome back" message appears on the page only when the underlying query's `WHERE` condition evaluates true for the current session. That behavioral difference is the oracle.

## Steps to Reproduce

1. Intercepted a request and identified the `TrackingId` cookie as the likely injection point.
2. Confirmed the injection and the oracle by sending two near-identical payloads and comparing the response:
   ```
   TrackingId=xyz' AND '1'='1
   TrackingId=xyz' AND '1'='2
   ```
   The first (always-true condition) produced the "Welcome back" message; the second (always-false) did not — confirming both that the cookie is injectable and that the page's behavior is a reliable true/false signal.
3. Confirmed the `users` table and the `administrator` account exist using the same boolean technique:
   ```
   TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
   ```
   The "Welcome back" message appearing confirmed the row exists.
4. Extracted the administrator's password length by testing `LENGTH(password)` against increasing values until the condition flipped from false to true:
   ```
   TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>N
   ```
5. Extracted the password one character at a time using `SUBSTRING`, binary-searching each character's value by comparing against ASCII ranges (or testing one character guess at a time), repeating across every character position until the full password was recovered:
   ```
   TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
   ```
6. Logged in as `administrator` with the recovered password to complete the lab.

## Why This Works

Even with zero visibility into the query's actual output, a single reliable true/false signal in the application's behavior is enough to extract arbitrary data — one bit (or one character) at a time — by repeatedly asking the database true/false questions through the injection point. It's slower than a UNION attack, but it doesn't require the query to ever display its results.

## Remediation

- Parameterized queries, same as every other finding in this path — this entirely prevents the injection regardless of whether the query's output is visible.
- Avoid conditional application behavior (differing messages, timing, response size) being driven by unsanitized input in a query at all — this is what gives a blind injection its oracle in the first place.

## What I Learned

This lab was the shift from "can I see the data" to "can I infer the data" — automating the character-by-character extraction (even manually in Burp Repeater, testing one character at a time) made clear why real-world blind SQLi exploitation is typically scripted rather than done by hand one request at a time.
