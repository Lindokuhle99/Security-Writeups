# SQL Injection Attack, Listing the Database Contents on Non-Oracle Databases

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

Same UNION-based injection point as the earlier labs (`category` parameter, two-column, text-compatible result set). This time the goal is to go beyond fingerprinting the database and actually enumerate its schema and then extract credentials — without any prior knowledge of table or column names.

## Steps to Reproduce

1. Re-confirmed the injection point, column count (2), and that both columns render as text.
2. Queried the standard `information_schema.tables` view, available on MySQL, Microsoft SQL Server, and PostgreSQL, to list every table in the current database:
   ```
   ' UNION SELECT table_name, NULL FROM information_schema.tables--
   ```
   This returned a list of table names, including one that stood out as holding credentials (a `users`-style table).
3. Queried `information_schema.columns`, filtered to that table, to find its column names:
   ```
   ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = '<table_name>'--
   ```
   This revealed the username and password column names.
4. With the table and column names known, extracted the actual credential data:
   ```
   ' UNION SELECT username, password FROM <table_name>--
   ```
5. Used the recovered administrator credentials to log in and complete the lab.

## Why This Works

`information_schema` is a standard, built-in metadata schema present in MySQL, Microsoft SQL Server, and PostgreSQL (Oracle uses a different mechanism — `ALL_TABLES`/`ALL_TAB_COLUMNS` — which is why this technique is scoped to non-Oracle databases). Because it's queryable like any other table via the same UNION injection point, an attacker with no prior knowledge of the schema can enumerate it entirely from the outside, then pivot straight to extracting real data.

## Remediation

- Parameterized queries remain the primary fix — this entire enumeration chain depends on the UNION injection existing at all.
- Restrict the database account used by the application so it cannot read `information_schema` (or equivalent) for tables it doesn't own, where supported.
- Store passwords hashed (not that this lab's design is about hash cracking — but in a real system, extracting a hashed value is a meaningfully smaller breach than extracting it in plaintext).

## What I Learned

This lab is really where UNION injection becomes a full attack chain rather than a trick: fingerprint the engine → enumerate the schema → extract targeted data, all through one injection point and no prior knowledge of the application's database design.
