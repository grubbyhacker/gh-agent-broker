# Coordinator session API v1

`broker/coordinator/v1` is the private, authenticated Signal Plane boundary for
authority-worker sessions. It is disabled whenever no authority principals are
configured. It does not activate a production route.

All operations are under `/v1/authority-workers/coordinator/v1`:

- `POST /leases` acquires a broker-selected worker for a reviewed profile.
- `POST /sessions/create` creates the broker-recorded agentd session.
- `POST /sessions/submit`, `/events`, `/checkpoint`, `/resume`, `/cancel`, and
  `/status` proxy only the corresponding fixed agentd operation.
- `POST /reassign` performs the broker-owned lease/adoption transition.
- `POST /reassignments/status` returns the durable adoption state for one
  predecessor fence epoch.

The session operations accept a logical `session_binding` and only their
operation-specific fields. Unknown fields fail strict JSON decoding. They never
accept a worker ID, agentd session ID, profile, image, runtime, model, endpoint,
credential, command, mount, network, or policy. The broker resolves the active
lease, exact profile version and policy digest, session and storage lineages,
worker fence, workspace, agentd identity, Docker address, port, and coordinator
credential from durable state and reviewed configuration.

Lease responses include the complete immutable routing identity:
`profile`, `profile_version`, `policy_digest`, `worker_id`,
`session_lineage_id`, `worker_storage_lineage_id`, and
`worker_fence_epoch`. The stable cross-repository JSON fixtures are in
`testdata/coordinator-wire/`.

Reassignment is a durable saga. The broker transaction transfers capacity,
lease ownership, workspace association, and writes a pending adoption before
calling agentd. History is unique per logical binding and predecessor fence
epoch, so later worker generations append new transitions. Status reads are
scoped to the authenticated principal and authorized profile; another principal
cannot inspect current or historical adoption state. The states are `pending`,
`confirmed`, `conflict`, and `legacy_unresolved`.
