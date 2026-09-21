# Specialized task and audit request evidence

Issue #660 reconciles the remaining 16 task-family semantic operations:
import/container, agent-group, OCI/container-image, and web-application task
creation; `move_task`; and audit list, detail, create, clone, modify, delete,
start, stop, and resume.

## Evidence baseline

The authoritative repository pin is gvmd commit
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The review also compared current gvmd commit `8525407f910f...` dated
2026-09-18 and python-gvm v27.8.0 commit `1bb3782b6253...`. Current gvmd does
not change the successful shapes below. python-gvm remains interoperability
evidence, not the protocol authority.

The published
[`create_task` grammar](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L6497)
lists the mutually exclusive standard, agent-group, OCI-image, and
web-application target elements. Query and modification grammar is recorded at
[`get_tasks`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L32102)
and
[`modify_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L39415).

## Specialized creation

- Import tasks are exactly name, optional comment, and `<target id="0"/>`.
  The pinned handler completes them immediately. The compatibility name
  `CreateContainerTaskRequest` intentionally has the same shape; it is not a
  container-image scan.
- Agent-group tasks require a group but not a configuration. A scanner is
  optional: gvmd derives it from the group when omitted and rejects an
  explicitly different scanner. This is implemented in
  [`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L25799).
- OCI-image and web-application tasks require their specialized target and the
  matching scanner type, but no standard target or configuration. They retain
  the common comment, alterable, schedule, schedule-period, alert, observer,
  and preference structure. `CreateContainerImageTaskRequest` is the semantic
  compatibility alias for the OCI wire shape.
- Schedule periods are independent of schedule presence. `in_assets` is
  invalid for container-image and web scanners. Web scanners additionally
  constrain `scan_mode` to `active`/`safe` and require a non-negative integer
  `ajax_spider_timeout`; these return paths are defined by pinned
  [`set_task_preferences`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2011).
- Agent-group, OCI/container-image, and web-application semantic operations
  remain gated at GMP 22.8 before encoding or transport. Their common
  `create_task` wire root does not erase that semantic version identity.

## Move semantics

Pinned `move_task` requires both `task_id` and `slave_id`. An empty
`slave_id` means the master/default scanner; omission is an error. A nonempty
destination must resolve to a slave-capable OpenVAS scanner, and the source
task must itself use an OpenVAS scanner. The dispatch and result mapping are in
[`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L29252).
`TaskMoveDestination` therefore makes master versus a selected slave explicit.

## Audit identity and lifecycle

- Audits are task rows with `usage_type=audit`. List and detail always send
  that query scope; create sends it as a child and maps `policy_id` to gvmd's
  `config` relationship. Clone inherits the source task's usage type.
- Modify, delete, start, stop, and resume select a task by ID. Pinned
  `modify_task_data_t` has no usage-type field and the parser has no
  `USAGE_TYPE` branch, so `ModifyAuditRequest` must not emit one. The canonical
  request retains audit identity in its Rust type while gvmd resolves identity
  from the selected row.
- Audit modification shares only real task update structure: name, explicit
  comment clearing, alterable, schedule, target, policy/config, scanner,
  alerts, observers, and preferences. Because users and groups share the
  `<observers>` container, every group update requires an explicit user
  replace/clear before any support check or transport.
- Clone owns its audit copy source plus the comment and alterable overrides
  actually applied by gvmd. Delete owns `ultimate`; each action request owns
  its audit identifier and preserves the standard report-producing task state
  transitions.

## Bounded mock behavior

The stateful mock derives and validates agent-group scanners, enforces
container/web scanner types and their preference restrictions, and swaps
candidate resources only after every relationship validates. `move_task`
requires the destination attribute, validates both scanners, and changes the
relationship atomically. Audit tests cover usage-scoped list/detail,
creation, inherited clone identity, modification and rollback, start/stop/
resume report state, trash deletion, and ultimate deletion. The mock does not
model gvmd's permissions engine, asynchronous scanner control, or the full
slave capability negotiation.
