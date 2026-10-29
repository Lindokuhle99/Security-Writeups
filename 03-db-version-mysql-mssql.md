# SQL Injection Attack, Querying the Database Type and Version on MySQL and Microsoft

**Source:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Status:** Solved

## Vulnerability

The product category filter is vulnerable to UNION-based SQL injection: the underlying query returns results displayed directly on the page, which means a `UNION SELECT` can be used to pull arbitrary data into the response — including information about the database engine itself.

## Steps to Reproduce

1. Confirmed the injection point via the `category` parameter, as in the earlier labs.
2. Determined the query returns two columns (confirmed via `ORDER BY` incrementing until an error, then `UNION SELECT NULL,NULL--` succeeding).
3. Confirmed both columns accept text by testing:
   ```
   ' UNION SELECT 'a','a'--
   ```
4. Queried the database version using MySQL/Microsoft's version function, since this platform doesn't use Oracle's `DUAL` table requirement:
   ```
   ' UNION SELECT @@version, NULL--
   ```
5. The response rendered the database version string directly on the page (MySQL or Microsoft SQL Server, both support `@@version` without needing a `FROM` clause), confirming the database type and its exact version.

## Why This Works

Because the application displays query results on the page, a successful `UNION SELECT` lets you append arbitrary data of your choosing to the legitimate result set — as long as the column count and types line up. `@@version` is a built-in system variable in both MySQL and Microsoft SQL Server, so it requires no table reference at all, which is what makes it usable the moment you've confirmed the column count and a text-compatible column.

## Remediation

- Parameterize all queries so UNION injection isn't possible in the first place.
- Don't expose verbose database information (version strings, engine type) in error messages or query results even for authenticated/internal use — this is reconnaissance an attacker should never get for free.
- Apply a Web Application Firewall as defense-in-depth, though it should never be relied on as the primary fix.

## What I Learned

Fingerprinting the database engine is usually the first real step after confirming a UNION injection — knowing whether you're dealing with MySQL, MSSQL, Oracle, or PostgreSQL changes which system functions and syntax are available for every subsequent step (like listing tables).
