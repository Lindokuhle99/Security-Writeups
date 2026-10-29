# SQL Injection Vulnerability Allowing Login Bypass

**Source:** PortSwigger Web Security Academy
**Difficulty:** Apprentice
**Status:** Solved

## Vulnerability

The login form checks credentials with a query built by concatenating the submitted username and password directly into SQL, roughly:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>'
```

Because the username field isn't sanitized, it's possible to inject SQL that changes the authentication logic itself.

## Steps to Reproduce

1. Intercepted the login request in Burp Proxy and sent it to Repeater.
2. In the `username` field, submitted:
   ```
   administrator'--
   ```
   leaving the password field as anything.
3. The resulting query becomes:
   ```sql
   SELECT * FROM users WHERE username = 'administrator'--' AND password = '...'
   ```
   The `--` comments out the rest of the query, including the password check entirely. The query now just checks whether a user named `administrator` exists — which it does — and logs that session in as `administrator` with no valid password required.
4. Submitted the request and confirmed the response logged the session in as the administrator account.

## Why This Works

The password check exists entirely inside the string the application builds — once the username field lets you terminate that string and add a comment, the password condition is simply never evaluated. The query's logic was rewritten by the input, not by any flaw in the password itself.

## Remediation

- Use parameterized queries so the structure of the query (including the `AND` condition) can never be altered by user input.
- Never trust that a comment-breaking character like `'` can't reach the query — always validate and/or escape at the data layer, not just the UI.
- Rate-limit and monitor login attempts, since this class of bug is often probed for with automated single-quote tests.

## What I Learned

This is the classic demonstration of why authentication logic should never be expressed as raw SQL string concatenation — the entire password check can be erased with a two-character comment sequence.
