# Typed schema projection evidence

Issue [#715](https://github.com/greenbone-hive/rust-gvm/issues/715)
adds five bounded typed projections. The source of truth for this layer is
public gvmd commit
[`5385fcb0130bb15230ada02effb78fab74c166b1`](https://github.com/greenbone/gvmd/commit/5385fcb0130bb15230ada02effb78fab74c166b1).
This is source/schema evidence, not a live-gvmd transcript.

## Agent support-bundle encryption

[`get_agent_support_bundle_start`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_agent_support_bundle.c#L66)
reads `encryption` as a root attribute. The dedicated
[parser](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_agent_support_bundle.c#L125)
uses integer parsing, accepts only `0` and `1`, and defaults an omitted value to
`1`. The run handler passes that value to the support-bundle operation
([line 280](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_agent_support_bundle.c#L280)).
The schema independently documents the optional integer attribute and its
encrypted default
([line 9939](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L9939)).

`GetAgentSupportBundleRequest::encryption` is therefore `Option<bool>` and
encodes as `0`/`1`. `None` emits no attribute and preserves gvmd's default. The
existing two-argument constructor remains unchanged and initializes the new
field to `None`.

## Result NVT type metadata

The result renderer obtains
[`result_iterator_vt_type_metadata`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp.c#L10122)
and emits a nonblank value as `<type_metadata>` inside the result's `<nvt>`
([line 10237](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp.c#L10237)).
`NvtRef::type_metadata` preserves that payload as optional text. It is not
interpreted as JSON, so type-specific content is retained after XML entity
decoding.

## NVT discovery and technical information

Both the full and compact NVT rendering branches emit integer
[`<discovery>`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/manage.c#L5277).
The common NVT schema describes it as the discovery marker
([line 720](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L720)).
`Nvt::discovery` and the NVT `get_info` payload preserve `0`/`1` as an optional
boolean and reject other values instead of silently coercing them.

When the internal detailed-NVT flag is enabled, the renderer adds
[`<tech_info><description_md>`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/manage.c#L5283).
Generic NVT `get_info` passes its `details` value into that flag
([line 15127](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp.c#L15127)).
`GenericInfoPayload::Nvt` retains the nested `NvtTechInfo::description_md`,
including a present but empty description.

## Web-application VT subtype and future subtypes

The handler recognizes `web_application_vt` only when the web-application
scanning feature is enabled, checks that its database is loaded, selects the
dedicated iterator, and records the subtype
([lines 14712–14823](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp.c#L14712)).
Its response contains type, description, solution, severity, JSON-text
`type_metadata`, and repeated references
([lines 15096–15125](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp.c#L15096)).
The schema lists the subtype and the same payload fields
([line 18379](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L18379)).

`GenericInfoType::WebApplicationVt` makes the implemented branch reachable.
`GenericInfoPayload::WebApplicationVt` retains every emitted field and
reference. The implementation emits reference attribute `id`, while the
schema says `ref_id`; the decoder follows real gvmd and also accepts the schema
spelling as a compatibility fallback.

The existing `GenericInfo::info_type` string remains the public discriminator.
For an unrecognized future direct subtype child, the decoder now retains the
enclosing item and puts the raw child name in `info_type`, with
`GenericInfoPayload::Unknown`. Unknown fields alongside a recognized subtype
remain ignored, preserving the response parser's additive-field tolerance.

## Deliberate boundary

This layer does not add EPSS projections, live-gvmd E2E coverage, or the
separate error-regression phase. The existing mock accepts and records the
new support-bundle attribute without inventing backend encryption behavior;
the response projections are proven with source-shaped parser fixtures.
