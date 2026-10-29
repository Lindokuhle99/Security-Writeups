# SQL Injection UNION Attack, Retrieving Data from Other Tables

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

Same UNION injection point, with column count (2) and a usable text column already confirmed. This lab's twist: unlike the "listing database contents" lab, the table and column names are given up front (`users` table, `username`/`password` columns) — the focus here is purely on constructing the UNION to pull data from a completely different table than the one the original query targets.

## Steps to Reproduce

1. Confirmed column count and text-compatible column position as in the previous two labs.
2. Built a UNION that selects from the `users` table instead of the application's `products` table:
   ```
   ' UNION SELECT username, password FROM users--
   ```
3. The response rendered the credential pairs from the `users` table directly into the product listing page — since both selected columns lined up with the text-compatible positions already established.
4. Logged in using the extracted administrator credentials to complete the lab.

## Why This Works

A UNION injection isn't limited to querying the same table the original statement targets — as long as the column count and types match, the injected `SELECT` can reference any table the database user has permission to read. This is the step that turns a UNION injection from "I can manipulate this one table's results" into "I can read the entire database."

## Remediation

- Parameterized queries, as throughout this path.
- Principle of least privilege on the database account the web app uses — if it only needs read access to `products`, it shouldn't have read access to `users` at all.

## What I Learned

This lab made it concrete that a UNION injection's real risk isn't limited to the table being queried on-screen — it's the entire database the connection's privileges allow access to.
