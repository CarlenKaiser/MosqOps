# Security Policy

## Supported Versions

This project is pre-1.0. Security fixes are applied on the default branch.

## Reporting A Vulnerability

Please do not disclose security vulnerabilities in public issues.

Instead, contact the maintainer privately with:

- A clear description of the issue
- Impact and potential exploitation path
- Reproduction steps or proof of concept
- Any suggested remediation

If possible, include:

- Mosquitto version
- Runtime/container details
- Relevant config snippets with secrets removed

You can expect an initial response within 7 days.

## Hardening Notes

- The embedded HTTP API currently has no built-in authentication.
- Run behind an authenticated reverse proxy and/or private network segment.
- Restrict network exposure of port `8080`.
