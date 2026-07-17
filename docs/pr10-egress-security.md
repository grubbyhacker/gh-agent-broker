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
  payloads represented in those results, are scanned before status handling,
  validation, or response serialization. Non-success agentd codes are reduced
  to a fixed safe enum.
- Both broker audit serializers scan the fully rendered JSON event. A finding
  replaces the event with a bounded, sanitized security event rather than
  writing the unsafe event.
- Canonical scanning covers bounded raw, URL-escaped, hex, base64, and
  base64url representations through two decoding layers. Broker-controlled
  field and stream sequences are scanned without separators so split matches
  fail closed. Candidate count, decoded bytes, field bytes, and stream bytes
  all have explicit fail-closed limits.
- Every collected artifact and lesson file is scanned before either inline
  content or a hash-only manifest is returned. Files beyond the 16 MiB stream
  bound are denied as unscanned rather than returned.

These checks halt credential issuance for the attempted GitHub operation:
textual mutations are denied before the broker asks GitHub for an installation
token. They do not create a durable global quarantine or revoke credentials
that may already exist for unrelated operations.

## Deliberate limits

- Git pushes use Git smart HTTP, whose commit trees and messages arrive inside
  opaque packfiles. Agents configured with
  `git_receive_pack_policy: deny_opaque` are denied before branch-lifecycle
  probes, installation-token issuance, or upstream forwarding. Existing
  legacy identities default to `allow_opaque`; any credential-bearing authority
  worker must use a dedicated broker identity configured `deny_opaque` until a
  reviewed semantic receive-pack inspector exists.
- The scanner is a deterministic credential-shape detector, not a general
  content classifier or malware scanner.
- Durable worker quarantine, worker maximum-age enforcement, global credential
  issuance halt, credential revocation, semantic Git pack inspection, and
  production policy activation are
  outside this staged subset. They require explicit lifecycle/store policy and
  deployment-owner contracts rather than a process-local side effect.

No production configuration or real credential material is introduced or
read by this boundary.
