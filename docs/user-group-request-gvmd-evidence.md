# User and group request gvmd evidence

The canonical user and group requests are based on the public gvmd source
pinned for this migration:

- gvmd commit
  [`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in)
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c)
- [`manage_sql_users.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c)
- [`manage_sql_groups.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_groups.c)

## Required values and semantic aliases

The create-user handler rejects an absent or empty name before calling the
management layer at
[`gmp.c` lines 26192–26265](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L26192).
It forwards password, comment, hosts and allow mode, authentication sources,
groups, and roles as one operation. The create-group handler likewise requires
a non-empty name and forwards comment, users, and the special-full flag at
[`gmp.c` lines 23852–23965](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L23852).
`CreateUserRequest` and `CreateGroupRequest` therefore own those complete
inputs and validate their final names before transport.

Detail retrieval remains a semantic operation over each plural list command,
and cloning remains a semantic operation over each create command. The clone
branches call `copy_user` and `copy_group` at the same handler locations above.
The Rust detail and clone request types keep those semantic identities while
encoding the shared wire roots.

## User relationships, host access, and authentication

User creation validates the host expression and inserts the requested group
and role relationships at
[`manage_sql_users.c` lines 635–850](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c#L635).
On modification, omitted groups and roles preserve the existing relationships;
present collections first replace them, and the sentinel identifier `0`
represents an explicit empty replacement. The group and role replacement loops
start at
[`manage_sql_users.c` lines 1990–2045](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c#L1990).
`CollectionUpdate` models preserve, replace, and clear explicitly.

Host access has a different boundary. The GMP parser initializes an encountered
`HOSTS` element even when it is empty at
[`gmp.c` lines 7455–7464](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L7455),
and the management layer writes a final cleaned host expression and allow mode
on every modification at
[`manage_sql_users.c` lines 1893–1978](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c#L1893).
`ModifyUserRequest` consequently requires the final `UserHostAccess` value.
Name, comment, password, authentication source, roles, and groups retain their
documented preservation or explicit-clear forms. Password-bearing requests use
custom debug output, and the client wire trace redacts password elements before
observation.

User deletion accepts either identifier or name and optional inheritance by
identifier or name. Identifier selection takes precedence in the management
layer at
[`manage_sql_users.c` lines 940–1010](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c#L940).
The canonical request rejects ambiguous selectors and ambiguous inheritors
before transport.

## User deletion has no `ultimate` input

At the pinned commit, the supported deletion input is a user selector and an
optional inheritor selector. Three independent layers agree:

- [`GMP.xml.in` lines 8548–8593](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L8548-L8593)
  defines `user_id` or `name`, with optional `inheritor_id` or
  `inheritor_name`. It does not define `ultimate`.
- The [`DELETE_USER` parser branch, `gmp.c` lines 5461–5474](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5461-L5474)
  reads only those four attributes. It never parses `ultimate`.
- The [handler call, `gmp.c` lines 22228–22234](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L22228-L22234)
  passes the selectors and a constant `1` to the
  [management function, `manage_sql_users.c` lines 938–955](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_users.c#L938-L955).
  That integer is `forbid_super_admin`, not an ultimate/trash switch; the
  function has no `ultimate` argument.

The internal [`delete_user_data_t`, `gmp.c` lines 1721–1731](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L1721-L1731)
retains a stale `ultimate` member and trashcan comment. Neither the parser nor
the management call uses it, so the declaration is not evidence of a supported
wire input.

The [v0.6.0 Rust builder](https://github.com/greenbone-hive/rust-gvm/blob/v0.6.0/crates/gvm-gmp/src/commands/users.rs#L177-L184)
accepted `delete_user(&user_id, ultimate)` and serialized the boolean. The
pinned gvmd implementation ignores that attribute. Removing it from
`DeleteUserRequest` is an intentional protocol-drift correction under #602 and
ADR 0002, not loss of a supported deletion mode. Both old boolean values migrate
to the same canonical request. See the
[v0.7 user/group migration](v0.7.0-migration.md#users-and-groups) for selector
and inheritance mapping. Exact-wire tests in `test_users.rs` guard the supported
attribute set; they do not substitute for live-gvmd conformance testing.

## Group replacement behavior

The modify-group parser initializes name, comment, and users to empty values
when their elements are encountered at
[`gmp.c` lines 6970–6986](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L6970).
The handler passes all three values directly to `modify_group` at
[`gmp.c` lines 27345–27405](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L27345),
and the management implementation replaces the stored name, comment, and
membership. `ModifyGroupRequest` therefore requires all three final values;
empty comment and user values express explicit clearing.

The stateful mock lifecycle covers list, detail, create, clone, modify, and
delete for both resources, including group membership, user group assignment,
host access, authentication source, replacement, and clearing. These
deterministic checks validate the modeled contract but are not a claim of
live-gvmd interoperability.
