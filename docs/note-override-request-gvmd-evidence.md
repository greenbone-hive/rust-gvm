# Note and override request gvmd evidence

The canonical note and override requests are based on the public gvmd source
pinned for this migration:

- gvmd commit
  [`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in)
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c)
- [`manage_sql_notes.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_notes.c)
- [`manage_sql_overrides.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_overrides.c)

## Required create and modify values

The create-note handler requires an NVT entity and text before it calls the
management layer at
[`gmp.c` lines 23976–24083](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L23976).
Create override has the same NVT/text requirements and additionally requires
either `NEW_THREAT` or `NEW_SEVERITY` at
[`gmp.c` lines 24149–24265](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L24149).
The Rust API does not expose the deprecated threat spelling, so
`CreateOverrideRequest` requires the numeric replacement severity directly.

Both modify handlers require text. The note path is visible at
[`gmp.c` lines 27441–27470](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L27441),
while the override path forwards the final replacement severity at
[`gmp.c` lines 27561–27606](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L27561).
The management layer rejects an override modification with neither replacement
severity nor replacement threat at
[`manage_sql_overrides.c` lines 479–515](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_overrides.c#L479).
`ModifyOverrideRequest` therefore requires `new_severity` as a final value.

## Restriction, activation, and clone semantics

The note management functions validate result-port syntax and accept original
severity only in `0..=10` or the log value `-1`; the create behavior is at
[`manage_sql_notes.c` lines 50–128](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_notes.c#L50).
The override implementation uses the same original-severity range and also
accepts `-3` for false-positive replacement severity at
[`manage_sql_overrides.c` lines 43–163](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_overrides.c#L43).
Activation accepts `-1` for forever, `0` for disabled, or a positive number of
days. Omitted activation preserves the stored value on modify.

Modify is replacement-oriented for hosts, port, original severity, task, and
result: omission reaches the SQL layer as null/zero and clears each
restriction. NVT is updated only when supplied, and omitted activation is the
other preservation case. The note behavior is implemented at
[`manage_sql_notes.c` lines 287–390](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_notes.c#L287);
the override implementation starts at
[`manage_sql_overrides.c` line 391](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_overrides.c#L391).

Clone is a semantic operation over the create command and accepts only a
`copy` identifier. `copy_note` copies NVT, text, restrictions, relationships,
and end time at
[`manage_sql_notes.c` lines 159–166](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_notes.c#L159),
and `copy_override` also copies replacement severity at
[`manage_sql_overrides.c` lines 233–241](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_overrides.c#L233).

## Corrected transitional drift

The former note encoder emitted an `orphan` child. It is absent from the
pinned create/modify schemas and parser states, so gvmd merely read over it;
the canonical requests remove that unsupported input. Exact XML tests lock the
supported children, and client tests prove invalid final values fail before
support checks or transport.

The stateful mock lifecycle covers list, detail, create, clone, modify,
restriction clearing, NVT/activation preservation, and deletion for both
resources. These deterministic checks validate the modeled contract but are
not a claim of live-gvmd interoperability.
