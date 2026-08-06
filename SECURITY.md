# Security policy

Umbra is security-sensitive infrastructure. Please report suspected vulnerabilities privately and give maintainers a reasonable opportunity to investigate before public disclosure.

## Supported versions

Before 1.0, only the latest published release receives security fixes. After a new release is available, older pre-1.0 releases are unsupported. The project will document a longer support window before declaring a stable 1.x line.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** action in this repository's Security tab. It creates a private security advisory visible only to the reporter and the repository's security maintainers. If that action is unavailable, contact the organization maintainers through GitHub and ask for a private reporting channel without including exploit details in the initial message.

Include the affected version or commit, component, prerequisites, impact, reproduction steps, and any suggested mitigation. Remove tokens, personal data, live infrastructure identifiers, and unrelated secrets from evidence.

We aim to acknowledge a complete report within five business days. This is a target, not a service-level guarantee. Triage, remediation, release timing, and coordinated disclosure depend on severity and complexity. Maintainers will credit reporters who request credit and will respect requests for anonymity.

## Scope reminders

High-value areas include authentication and authorization, tenant isolation, attestation verification, Dev CVM isolation, Security CVM policy enforcement, DLP and secret injection, audit integrity, release provenance, and CI/CD credential boundaries. Reports about third-party hosted services may need to be coordinated with their operators.

Do not test against infrastructure or tenants you do not own, degrade service, access other users' data, or retain sensitive data beyond what is needed to demonstrate the issue.
