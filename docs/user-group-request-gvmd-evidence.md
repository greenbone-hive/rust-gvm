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
