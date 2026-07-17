# PR10 Broker Egress Security Boundary

This staged PR10 slice adds fail-closed, value-independent scanning at the
output boundaries that `gh-agent-broker` owns. The scanner recognizes a
synthetic PR10 canary and common credential shapes without loading, comparing,
or recording real secret values. A finding returns only a stable reason code
and field name, emits a sanitized `security.egress_blocked` audit event, and
denies the operation.

## Enforced surfaces

- Pull request creation, issue creation, issue comments, pull-review dismissal
  messages, and review-thread resolution messages are scanned after broker
  metadata rendering and before GitHub installation-token issuance or mutation.
- Sandbox logs are scanned before their redacted response is returned.
- Small text artifacts and lessons are scanned before their inline content is
  returned. Manifest paths are scanned for every collected file.
- Successful raw agentd session-command results, including event and evidence
  payloads represented in those results, are scanned before coordinator API
  validation and response serialization.
- Both broker audit serializers scan the fully rendered JSON event. A finding
  replaces the event with a bounded, sanitized security event rather than
  writing the unsafe event.

These checks halt credential issuance for the attempted GitHub operation:
textual mutations are denied before the broker asks GitHub for an installation
token. They do not create a durable global quarantine or revoke credentials
that may already exist for unrelated operations.

## Deliberate limits

- Git pushes use Git smart HTTP. Commit trees and messages arrive inside opaque
  packfiles, so this slice does not claim semantic commit-content scanning.
  Closing that gap requires a reviewed receive-pack inspection or verifier
  boundary that can parse the negotiated object graph before forwarding it.
- Files larger than the inline limit are represented only by path, size, hash,
  and a truncation marker. Their paths are scanned, but their bytes are not an
  API egress payload and are not scanned by this collection path.
- The scanner is a deterministic credential-shape detector, not a general
  content classifier or malware scanner.
- Durable worker quarantine, worker maximum-age enforcement, global credential
  issuance halt, credential revocation, and production policy activation are
  outside this staged subset. They require explicit lifecycle/store policy and
  deployment-owner contracts rather than a process-local side effect.

No production configuration or real credential material is introduced or
read by this boundary.
