# Schedule request gvmd evidence

The canonical schedule requests are based on the public gvmd source pinned by
this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in)
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c)
- [`manage_sql_schedules.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_schedules.c)

## Create and clone

The create schema defines name, comment, copy, iCalendar, and timezone at
[lines 5984–6028](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L5984).
The handler requires a name and a non-empty iCalendar payload for ordinary
creation at
[lines 18661–18680](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L18661).
`CreateScheduleRequest` therefore owns both final values and validates them
before support checks or transport.

Timezone remains optional. The management layer uses the requested timezone,
then the current user's timezone, then UTC, and validates the resolved value at
[lines 69–100](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_schedules.c#L69).

Clone is a semantic operation over `create_schedule`. When `<copy>` is present,
the handler passes optional name and comment overrides to `copy_schedule` at
[lines 18612–18618](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L18612).

## List and detail

The `get_schedules` schema exposes the single-schedule selector and ordinary
GET filtering at
[lines 30060–30140](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L30060).
The detail request retains a distinct semantic name while emitting
`get_schedules schedule_id="…" details="1"`.

## Modify

The modify schema makes the identifier required and renders name, comment,
iCalendar, and timezone as optional children at
[lines 38928–38968](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L38928).
The handler is stricter than the schema: it rejects a missing or empty
iCalendar element before dispatch at
[lines 18759–18780](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L18759).
`ModifyScheduleRequest` follows the executable handler contract and requires
the final iCalendar value even for name- or comment-only changes.

Omitted name, comment, and timezone preserve the current values. An explicit
empty comment clears it, while an empty timezone is treated as omission by the
management layer at
[lines 346–387](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_schedules.c#L346).

## Typed recurrence and evidence boundary

`ScheduleInput` remains a reusable typed recurrence value. Its canonical
iCalendar generation feeds the same create and modify request values used by
raw callers, so there is one semantic operation and one encoder for each wire
command.

The stateful mock lifecycle covers typed and raw construction, list/detail,
modify persistence, task relationships, comment clearing, and dependency-safe
deletion. These are deterministic integration tests, not a claim of live-gvmd
interoperability.
