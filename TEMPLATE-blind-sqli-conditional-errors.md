<!--
TEMPLATE — fill this in once you've actually solved the lab.
Delete this comment block and rename the file (drop "TEMPLATE-") when done.
-->

# Blind SQL Injection with Conditional Errors

**Source:** PortSwigger Web Security Academy — SQL injection / Blind SQL injection / Error-based
**Difficulty:** Practitioner
**Tools used:** Burp Suite Community Edition (Repeater), Chromium

## Vulnerability

The application sets a tracking cookie used in a backend SQL query. The query's result isn't reflected in the response, and the app behaves identically whether or not the query returns rows — **except** when the query causes a database error, in which case a custom error message is returned. This gives an oracle: inject a boolean condition into the cookie such that the query only errors when the condition is true (or false), and use the presence/absence of the error message to extract data one bit/character at a time.

## Steps to Reproduce

<!-- Fill in your real steps, e.g.: -->
1. Intercepted the request in Burp Proxy and sent it to Repeater.
2. Identified the `TrackingId` cookie as the injection point by appending `'` and observing <!-- what actually happened -->.
3. Confirmed the error-based oracle: a payload like `' AND (condition)--` caused the error page when `condition` was true/false — <!-- which way round, and what the actual error text/behavior was -->.
4. Built a boolean test to confirm the `users` table and `administrator` row exist: <!-- your actual payload -->.
5. Extracted the password length using <!-- technique: e.g. `SUBSTRING` + `LENGTH` combined with the CASE/error trick -->.
6. Extracted the password character by character: <!-- your actual payload pattern, e.g. using `CASE WHEN (condition) THEN (SELECT 1/0 ...) ELSE 1 END` to force an error -->.
7. Logged in as `administrator` with the recovered password to confirm.

## Evidence

<!-- Describe or embed screenshots of: the Repeater request/response pair showing the error flip, and the final successful login -->

## Why This Works

<!-- Your own explanation of why the error-triggering trick works as a side channel, in your own words -->

## Remediation

- Use parameterized queries / prepared statements everywhere — never build SQL from string concatenation of user input.
- Return generic error pages in production; never expose database error details to the client.
- Apply least-privilege database accounts so even a successful injection has minimal reach.

## What I Learned

<!-- A line or two in your own words — this is the part that actually reads as genuine in an interview -->
