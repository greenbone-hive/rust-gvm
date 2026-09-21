# Standard task request evidence

Issue #659 reconciles exactly nine standard scan-task operations against gvmd:
list, detail, create, clone, modify, delete, start, stop, and resume. Specialized
task creation, `move_task`, audit-scoped aliases, reports, and later system
families are outside this slice.

## Evidence baseline

The repository pin is gvmd commit
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The review compared that pin with current gvmd commit `8525407f...` on
2026-09-20. The current diff does not change the request shapes or successful
state transitions documented here; it only changes an internal `stop_task`
error path. The implementation therefore follows the repository pin.

The published grammar defines the standard create fields and preference shape
in [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L6497),
the query grammar at
[`get_tasks`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L32102),
the mutation grammar at
[`modify_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L39415),
and the action grammars at
[`resume_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L40150),
[`start_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L40296),
and [`stop_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L40347).

## Canonical request decisions

- `GetTasksRequest` owns the filter, saved-filter ID, trash, details,
  schedules-only, and pagination flags. `GetTaskRequest` is the semantic detail
  alias over `get_tasks` and always requests details for `usage_type=scan`.
- Standard create requires name, configuration, target, and scanner IDs. It
  also owns comment, alterable, schedule, schedule periods, alerts, observer
  users/groups, and ordered preferences. The parser and
  [`set_task_schedule_and_periods`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L6918)
  accept schedule periods without a schedule; omission while setting or
  clearing a schedule stores zero.
- `hosts_ordering` is intentionally absent. Pinned gvmd does not parse that
  create/modify child, the published create grammar does not contain it, and
  the database migration explicitly
  [drops the task column](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_migrators.c#L3767).
  The old request enum and option fields were therefore removed. Response
  parsing remains tolerant of the historical response element.
- Clone uses `<copy>` and supports the comment and alterable overrides that
  gvmd actually applies. An empty or omitted comment inherits the source.
  There is no name override: the pinned parser does not populate the value
  passed to [`copy_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L18331)
  from the ordinary create name during the copy path. The clone receives
  gvmd's unique derived name and copies alerts, observers, relationships, and
  preferences while resetting execution state.
- Modify uses `ScalarUpdate` for schedule preserve/set/clear and
  `CollectionUpdate` for alert and observer preserve/replace/clear. Target,
  configuration, and scanner are replace-or-preserve because ID `0` means
  preserve in the pinned implementation, not detach. Alert, observer-group,
  and schedule ID `0` values are the corresponding clear sentinels.
- Observer users are text inside the same `<observers>` container that holds
  group children. Opening that container for a group-only update makes the
  user text an explicit empty replacement in gvmd. Canonical validation
  therefore requires every group replacement/clear to carry an explicit user
  replacement/clear, preventing accidental user loss.
- Task preferences encode as `scanner_name` plus `value`. The pinned
  [`set_task_preferences`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2011)
  validates `auto_delete` as `keep` or `no` and constrains
  `auto_delete_data` to 2 through 1200. Canonical validation applies those
  rules to final mutated request values before capability checks or transport.
  Preference values are redacted from request `Debug` output and wire traces.
- Delete owns the `ultimate` decision. Start creates a report and returns its
  identifier; stop changes that report and task to Stopped; resume continues
  the same report and returns its identifier. Pinned dispatch and response
  construction are visible in
  [`resume_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L29483),
  [`start_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L29761),
  and [`stop_task`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L29891).

## Bounded mock behavior

The stateful mock validates production-shaped alert/group relationships,
schedule/config/target/scanner relationships, alterable state, and the pinned
task preferences before swapping a candidate task into the store. A failed
compound modification therefore leaves every field unchanged. It preserves
readable non-UUID relationship IDs used by older mock fixtures, but UUID-shaped
IDs receive real existence/type validation.

The mock also deep-copies task state, applies source-shaped clone overrides,
renders alerts/observers/preferences for observation, creates exactly one
report on start, and reuses it across stop/resume. It does not model gvmd's
complete permissions engine, scheduler, scanner-type-specific preference
matrix, or asynchronous Requested/Stop Requested timing.
