# SQL Injection UNION Attack, Finding a Column Containing Text

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

Same injection point, column count already established (previous lab). Knowing the column count isn't enough — to actually exfiltrate string data (like a username or password) through a UNION injection, at least one of those columns has to be a type that will accept and display a text string.

## Steps to Reproduce

1. Established the column count was 2 (as in the prior lab).
2. Tested each column position individually with a short string literal in place of `NULL`, to find which one(s) accept text without throwing a type-mismatch error:
   ```
   ' UNION SELECT 'a', NULL--
   ```
   If that errors, the first column isn't text-compatible — try the other position:
   ```
   ' UNION SELECT NULL, 'a'--
   ```
3. The position that returned successfully (with `'a'` visible somewhere on the rendered page) is the usable text column for any future data extraction.

## Why This Works

Columns in the underlying query have fixed data types (integer, text, date, etc.), and most databases will throw a type-conversion error if you try to UNION a string literal into a numeric column. Substituting `NULL` into a column always works regardless of type (since NULL is valid everywhere), which is exactly why the earlier column-count lab used `NULL` to avoid this exact problem — but to actually get readable data out, at least one column needs to be swapped from `NULL` to a real string, and this lab is about finding which position tolerates that.

## Remediation

Same root cause and fix as the rest of the path — parameterized queries. There's no column-type-specific mitigation here; the vulnerability is the ability to inject a UNION at all.

## What I Learned

This is a small but necessary step between "I can UNION inject" and "I can actually read data out" — a lot of real-world UNION attacks stall here if you don't methodically test each column position rather than assuming the first one works.
