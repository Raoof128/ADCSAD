# ESC1–ESC8 Reference

- **ESC1**: Everyone can enroll and supply Subject Alternative Names.
- **ESC2**: Enrollment agent templates allow on-behalf requests without approval.
- **ESC3**: Dangerous EKUs such as `CertificateRequestAgent` on non-agent templates.
- **ESC4**: AnyPurpose or no EKU templates enabling service impersonation.
- **ESC5**: CA permissions allow unprivileged users to manage CA or certificates.
- **ESC6**: Subordinate CA templates issue signing certificates freely.
- **ESC7**: Weak cryptography (RSA < 2048, MD5/SHA1 signatures).
- **ESC8**: NTLM relay to HTTP enrollment endpoints lacking EPA.

Refer to the attack and hardening scripts for concrete demonstrations and
remediation steps.
