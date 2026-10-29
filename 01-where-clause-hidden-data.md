# SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data

**Source:** PortSwigger Web Security Academy
**Difficulty:** Apprentice
**Status:** Solved

## Vulnerability

A shopping application lets users filter products by category via a URL parameter (`category`). That value is concatenated directly into a backend SQL query of the form:

```sql
SELECT * FROM products WHERE category = '<user input>' AND released = 1
```

Because the input isn't parameterized, it's possible to break out of the string literal and alter the query's logic.

## Steps to Reproduce

1. Browsed the product categories and noted the `category` parameter in the URL (e.g. `?category=Gifts`).
2. Tested for injection by appending a single quote — this broke the page, confirming the input lands directly in the SQL query.
3. Used a comment sequence to cut off the rest of the original query:
   ```
   ?category=Gifts'--
   ```
   The trailing `--` comments out the rest of the server's query (`AND released = 1`), so the filter on `released` no longer applies — any hidden/unreleased products in the "Gifts" category are returned.
4. To retrieve every hidden product regardless of category, used a tautology instead:
   ```
   ?category=Gifts' OR 1=1--
   ```
   This makes the `WHERE` clause true for every row, returning the full product table — including the unreleased item the lab is looking for.

## Why This Works

The application trusts user input as safe to place inside a SQL string literal. Once you can terminate that string and inject your own SQL, you control the query's logic entirely — here, bypassing a business-logic filter (`released = 1`) that was never meant to be user-controllable.

## Remediation

- Use parameterized queries / prepared statements so user input is always treated as data, never as part of the query structure.
- Apply least-privilege database accounts so even a successful injection has limited reach.
- Don't rely on application-layer filters (like `released`) as a security boundary if they can be bypassed via injection.

## What I Learned

This was the first lab in the path and it's the clearest illustration of *why* string concatenation in SQL is dangerous — a single unescaped quote is enough to hand an attacker control of the query logic.
