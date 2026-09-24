# Release provenance

This repository is the sanitized public reference for CNServerOps. It documents the architecture, safety model, packaging flow, and testable contracts without publishing operational credentials, firmware payloads, live endpoints, customer evidence, or private machine state.

## What the public branch represents

The current public history follows the `3.8.120` source lineage. It is useful for code review, architecture study, installer work, and controlled development, but it must not be described as an exact image of a deployed production SSD.

Production work continued in immutable, hardware-specific release lines. Preserved release artifacts show at least:

| Lineage | Preserved release | Purpose |
| --- | --- | --- |
| RS501 / ASMB11 | `3.8.168-rs501-empty-sel-no-events-strict` | Empty-SEL semantics and RS501 evidence finalization |
| RS720 / K15PP-D24 / ASMB12 | `3.8.186-rs720-k15pp-d24-asmb12-bmc-recovery-profile` | RS720 platform and BMC recovery contract |
| RS720 / ASMB12 | `3.8.193-rs720-native-sdlc-central-event-fix` | Native-log and Central completion-event corrections |
| RS720 / ASMB12 | `3.8.195-rs720-option7-final-summary-fix` | Inventory evidence final-summary correction |

These releases are evidence of later engineering work, not proof that every specialized change is suitable for the public cross-platform branch.

## Later validated findings not yet fully merged

Later physical work identified several generally useful behaviors:

- firmware versions may include vendor codenames such as `1302(Turin)` and require normalized comparison in every subsystem that compares versions;
- the ASUS-native BIOS OOB sequence on the validated RS720 required one persistent authenticated HTTP connection rather than a fresh `urllib` connection for every request;
- a genuinely empty SEL is a valid `EMPTY_SEL` / `NO_EVENTS` condition, distinct from authentication failure or unavailable collection;
- native SDLC, System Debug Log, SEL raw, and SEL text are different artifact types and must not be relabeled as one another;
- Central completion events must preserve BMC password-change state without sending a schema-invalid payload;
- final evidence summaries must be generated after delivery state is known when the summary claims delivery completion.

Before any of these behaviors is merged into the public branch, it should be isolated from machine-specific configuration, covered by focused tests, and run through the complete public regression suite.

## Deliberately excluded material

The public repository does not include:

- BMC or Central credentials, tokens, cookies, or private keys;
- proprietary firmware packages or vendor-generated diagnostic archives;
- live IP addresses, customer identifiers, system serials, or operational run archives;
- production release bundles and their private manifests;
- mutable state copied from a deployed runner.

This separation is intentional. A public source revision and a physical production release should be compared by explicit manifest and source provenance, never by a shared `3.8.x` label alone.
