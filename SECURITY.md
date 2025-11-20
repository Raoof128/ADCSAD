# Security Policy

## Reporting
Please report vulnerabilities via email to security@adcs-lab.example with as
much detail as possible (PoC, impact, environment, and suggested mitigations).
We acknowledge receipt within 2 business days.

## Supported Versions
This project is a lab; no formal releases exist. Security fixes will be
prioritized on `main`.

## Hardening Checklist
- Enforce Extended Protection for Authentication on ADCS HTTP endpoints.
- Restrict enrollment agents and remove ENROLLEE_SUPPLIES_SUBJECT where possible.
- Audit CA ACLs for ManageCA/ManageCertificates rights.
- Raise minimum key sizes and remove AnyPurpose/NoEKU templates.
- Enable logging (Sysmon/Windows Event Forwarding) for certificate requests and CA changes.

## Coordinated Disclosure
If a vulnerability has broader ecosystem impact, we will coordinate publication
and credit with the reporter after remediation guidance is available.
