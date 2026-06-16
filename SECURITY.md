# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@vairav.net** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 48 hours and a resolution timeline within 5 business days.

## Security design notes

- All API endpoints require JWT authentication except `/auth/login` and the first-run `/auth/register`
- RBAC enforced at the dependency layer (`admin`, `analyst`, `viewer` roles)
- API keys and secrets are read exclusively from environment variables — never hardcoded
- Scanner uses passive/read-only discovery — no credentials are ever submitted to suspicious websites
- SSRF prevention: all URLs are validated before the scanner fetches them
- HTTP requests carry a non-browser User-Agent string and respect timeout limits
- Audit log records all user actions (status changes, scan triggers, report generation)
- Screenshots are stored server-side; the frontend displays paths, not raw binary over the API
- Rate limiting is applied at the API gateway level (configure via reverse proxy in production)
