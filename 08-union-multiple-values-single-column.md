# SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

Same injection point, but this time only **one** column in the original query is text-compatible (confirmed via the column-finding technique from an earlier lab) — meaning a straightforward `UNION SELECT username, password FROM users--` isn't possible, since there's nowhere to put the second value.

## Steps to Reproduce

1. Confirmed only one of the available columns accepts text.
2. Rather than selecting username and password into two separate columns, concatenated both values into the single available text column, separated by a distinct delimiter so they could be told apart in the output:
   ```
   ' UNION SELECT username || '~' || password FROM users--
   ```
   (Using `||` for standard SQL/Oracle-style string concatenation; the equivalent on MySQL would be `CONCAT(username, '~', password)`.)
3. The response rendered each row as a single combined string, e.g. `administrator~<password>`, in the one usable column.
4. Split on the `~` delimiter to recover the individual username and password values, and logged in as the administrator to complete the lab.

## Why This Works

A UNION's column count is fixed by the structure of the original query, not by how much data you want to retrieve — so when there's only one usable output column, the workaround is to pack multiple values into that single column using string concatenation and a delimiter that won't naturally appear in the data, then parse it apart client-side (visually, in this case).

## Remediation

Same root cause as the rest of the path — this is purely a technique for working around a *constraint* of the injection, not a separate vulnerability. Parameterized queries remain the fix.

## What I Learned

This is a good lesson in working within real-world constraints rather than assuming the "ideal" version of an attack (one column per value) will always be available — a single usable column is still enough to exfiltrate an entire row if you're willing to concatenate and parse.
