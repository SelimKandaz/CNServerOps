# Release provenance

This repository is the sanitized public reference for CNServerOps. It covers the architecture, safety model, and testable contracts, without publishing operational credentials, firmware payloads, live endpoints, or customer data.

## What the public branch represents

The public branch is meant for code review, architecture study, and installer work. It should not be treated as a byte-for-byte mirror of a deployed production system.

Production deployments run on separate, hardware-validated release lines that are not published in this repository. Those releases are tracked internally by manifest and source provenance.

## Deliberately excluded material

The public repository does not include:

- BMC or Central credentials, tokens, cookies, or private keys
- proprietary firmware packages or vendor-generated diagnostic archives
- live IP addresses, customer identifiers, system serials, or operational run archives
- production release bundles and their private manifests
- mutable state copied from a deployed system

This separation is intentional. A public source revision and a physical production release are compared by explicit manifest and provenance, not by a shared version label.
