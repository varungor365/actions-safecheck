# Security Policy

## Scope

`actions-safecheck` is a local, read-only static scanner. It does not execute workflow code, authenticate to GitHub, or transmit repository contents.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub’s private vulnerability reporting for this repository when available. If that channel is unavailable, contact the maintainer through the email listed on the GitHub profile and include a minimal reproduction, affected version, and suggested mitigation. Do not include live credentials or sensitive repository contents.

## Design expectations

Findings are advisory heuristics. A clean scan is not a security guarantee, and reports should be reviewed by a maintainer before workflow changes are made.
