# SQL Injection UNION Attack, Determining the Number of Columns Returned by the Query

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

Same `category` filter injection point. Before a UNION attack can work, the injected `SELECT` must return exactly the same number of columns as the original query — this lab is specifically about establishing that number with no visibility into the application's source.

## Steps to Reproduce

Two standard techniques exist for this; I used the `ORDER BY` method first to confirm, then cross-checked with `UNION SELECT NULL`:

1. **`ORDER BY` method** — incremented a column index until the database threw an error:
   ```
   ' ORDER BY 1--   (succeeds)
   ' ORDER BY 2--   (succeeds)
   ' ORDER BY 3--   (error: column index out of range)
   ```
   This confirms the original query returns exactly 2 columns — ordering by a column that doesn't exist throws a database error, which the application surfaces differently (or outright displays) compared to a successful request.
2. **`UNION SELECT NULL` method** — confirmed independently by incrementing the number of `NULL` placeholders until the UNION succeeded without error:
   ```
   ' UNION SELECT NULL--        (error: column count mismatch)
   ' UNION SELECT NULL,NULL--   (succeeds)
   ```
   `NULL` is used here specifically because it's valid for (almost) any data type, so it won't trigger a type-mismatch error even before the column count is correct — isolating column count as the only variable being tested.

## Why This Works

A `UNION SELECT` is only valid SQL if both halves of the union return the same number of columns, and corresponding columns are of compatible types. Since the attacker has no visibility into the real query's structure, both techniques above are just binary-search-style probing: increase a count, observe success vs. error, and stop once you hit the boundary.

## Remediation

- The fix is the same as every other finding in this path: parameterize queries so a UNION injection isn't possible regardless of column count.
- Ensure production error handling doesn't leak database-level error details (even the mere presence/absence of an error here is the oracle being exploited).

## What I Learned

This lab is foundational rather than flashy — every later UNION-based lab in the path depends on being able to reliably determine column count first. Having both the `ORDER BY` and `UNION SELECT NULL` techniques in hand matters because some applications suppress one kind of error but not the other.
