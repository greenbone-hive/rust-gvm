# Role and permission request gvmd evidence

This slice uses public gvmd source pinned at
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19),
the same revision as the preceding user/group slice. These are source-backed
contracts; neither the Rust mock tests nor python-gvm tests against that mock
constitute live-gvmd validation.

## Roles

The [create-role handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L24880)
requires a non-empty name and forwards comment and comma-separated users.
Its copy branch accepts name and comment overrides, with an existing role ID.
`CreateRoleRequest` owns those creation fields, and `CloneRoleRequest` carries
the copy ID and supported overrides. User names are validated for empty entries
before serialization.

[`modify_role`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_roles.c#L508)
writes `name ?: ""` and `comment ?: ""`, deletes role membership, and adds the
supplied users. Omission does **not** preserve any of those three values.
Following the canonical group pattern, `ModifyRoleRequest` requires a final
non-empty name, comment, and user vector. Empty comment and vector clear them.
The raw escape hatch remains available for server-accepted empty names.

[`copy_role`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_roles.c#L80)
copies the role and eligible permissions, but does not copy `role_users`.
Its permission predicate selects the old role as subject, requires a non-trash
subject, and copies command-level or ownerless permissions. The mock models
command-level copies and empty cloned membership; it has no ownerless built-in
permission or ACL model. Resource-scoped ordinary permissions remain with the
original role.

Role copy passes the unique-name flag to
[`copy_resource_lock`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_resources.c#L482).
When the request name is omitted or empty, that helper sends the stored name to
[`uniquify`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_pg.c#L624)
with the suffix ` Clone`. Numbering starts at 1 and advances until the name is
available for the owner, producing names such as `operators Clone 1` and
`operators Clone 2`. A non-empty explicit name is first checked against active
roles by `copy_resource_lock`; a collision returns 1 before the role insert,
and the create-role handler maps that result to a 400 syntax response. Because
`copy_role` performs the resource copy and eligible permission copy in one SQL
transaction, a collision cannot leave either copy behind. Trashed roles live
outside the active role table used by the name check, so their names are
reusable. The mock makes the same final-name decision under one store lock
before inserting either the role or its copied permissions, while preserving
automatic clone numbering.

## Permission subjects and resources

The [create-permission handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L24330)
passes name, comment, resource ID/type, and subject ID/type to management.
[`check_permission_args`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_permissions.c#L847)
requires a permission name and a subject with both an identifier and a type
(`user`, `group`, or `role`). `get_version` is not a grantable permission.
`CreatePermissionRequest` therefore requires name and `PermissionSubject`.

A resource is optional for ordinary command-level permissions. A supplied
resource ID can omit its type: gvmd derives it from the final permission name.
[`gmp_command_type`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_commands.c#L244)
uses the command suffix with its trailing plural `s` removed and validates the
result. The permission check handles asset host/OS lookup separately. `Super`
instead requires a resource and an explicit identity resource type on creation.
`PermissionResource` owns the ID and optional type; the reserved ID `0` belongs
to the clear operation, not a resource reference.

The client validates structural requirements and known invalid `Super`
combinations. Command availability, resource existence, ACLs, and combinations
requiring existing server state remain authoritative server checks. The mock
models the ordinary suffix inference and explicit `Super` identity references;
it does not implement the full authorization engine or asset lookup fallback.

[`modify_permission`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_permissions.c#L1589)
preserves omitted name, comment, resource identifier, subject identifier, and
subject type. Subject identifier and type may be updated independently. Resource types
are inferred again for ordinary commands; existing identity types can be reused
for `Super`. In particular, a type-only resource child preserves an existing
identity type: supply both resource ID and type for deterministic replacement. The request exposes independently optional subject fields and
resource type, plus `ScalarUpdate<EntityId>` for resource preservation,
replacement, or clearing. `Clear` encodes `<resource id="0"/>`. A partial update
is not rejected merely because the needed complementary value lives on gvmd.

Clearing the resource from an existing `Super` permission leaves no resource
for the final permission. `check_permission_args` returns its missing-resource
result, and the
[`modify_permission` handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L27735)
routes that result through the resource find-error response (404). The SQL
transaction rolls back the earlier comment update, so the failed modification
is atomic. `check_permission_args` validates a supplied non-identity `Super`
resource type before it resolves or clears the resource. Consequently,
`<resource id="0"><type>task</type></resource>` returns the malformed-resource
result (400), not the missing-resource result, and rolls back an accompanying
comment update. A clear without that malformed supplied type still returns
404. The stateful mock preserves the supplied type through final validation
and keeps that distinction.

The [modify parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L6994)
initializes an encountered comment even without character content. Thus
`Some("")` emits an empty comment and clears it, while `None` preserves it.

## Clones, detail aliases, and responses

Permission copying accepts only a comment override:
[`copy_permission`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_permissions.c#L1307)
retains name, resource, and subject. There is no typed permission-clone rename
field. Both [create parsers](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L7805)
do not initialize an empty comment, so empty and omitted clone comments both
preserve the original. Canonical encoders omit empty clone comment overrides.

Detail requests use `get_roles role_id="…" details="1"` and
`get_permissions permission_id="…" details="1"`. Clone requests use the create
root with a `copy` child. Semantic identities remain distinct from those shared
wire roots. The [common get attribute parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L45)
supports selectors, filters, saved filters, trash, and details. Existing response
associations and baseline GMP support remain unchanged.

The [permission response handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L15665)
always emits nested resource and subject references. Command-level permissions
have an empty resource identifier/name/type. The existing parser represents
that resource as absent; explicit fixtures now cover this shape and tolerate
trash/deleted/permissions metadata without losing the subject association.
