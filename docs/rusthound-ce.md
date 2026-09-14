# RustHound-CE v2.5.12 compatibility

Status: source review, reduced synthetic fixtures, and an authorized private lab
dump regression on Kali (2026-09-14). No live collection was initiated by this
test, and no upstream serializer execution or BloodHound CE ingestion comparison
was performed. The private JSON files are not stored in this repository.

Upstream tag: `v2.5.12`.
Commit: `aeb28db95f0149a1579c2517536083e150ae2803`.
Fixtures: [`tests/test_rusthound.py`](../tests/test_rusthound.py). All names and
identifiers are invented. They are handwritten excerpts of relevant fields,
not complete collector documents or a copied engagement collection.

## Builtin group placeholder collisions

RustHound-CE 2.5.12 and 2.5.13 append default builtin groups even when LDAP has
already supplied the same ObjectIdentifier. The reviewed `group.rs`, `sid.rs`,
checker entry point and `checker/common.rs` are byte-identical between these tags.
See the [2.5.13 checker](https://github.com/g0h4n/RustHound-CE/blob/v2.5.13/src/json/checker/common.rs)
and [group defaults](https://github.com/g0h4n/RustHound-CE/blob/v2.5.13/src/objects/group.rs).
This is not evidence of mixed collection snapshots by itself.

bhq recognizes exactly one actual record plus one source-matching empty default
for builtin RIDs 544, 548, 550, 554, 557, 560 and 561 within the same groups file.
It requires schema 6 and one of the two reviewed collectorversion strings. These
labels identify a compatibility rule, not proof of collector authenticity.
The actual record must identify a live builtin group in the matching domain;
the default must match the complete known shape, with no ACEs, members or extra
fields. WAAG's empty domain property is a specific upstream default.

The actual object is kept unchanged, regardless of record order. Normalizations
are recorded in `Graph.collection_normalizations` with the source file and
zero-based record indices, and shown in report diagnostics. Raw metadata counts
remain the original file counts, not the normalized graph counts. Files on disk
are never rewritten. Standalone defaults remain available; this is not a generic
deduplication or edge-union policy. Different files, unsupported versions,
multiple actual records, nonempty defaults and unknown fields still fail closed.
Conflicting records within one file now produce a distinct error from duplicates
across files.

[`tests/test_rusthound_duplicates.py`](../tests/test_rusthound_duplicates.py)
uses only invented records and includes order, ZIP, version and conflict cases.
On the private 2.5.12 lab dump, the original loader failed on seven duplicate
builtin IDs. The corrected loader retained every actual group unchanged and
passed the full report CLI; all 13 original JSON checksums were unchanged.
The dump was not recollected with 2.5.13: that version's claim is source and
synthetic-test compatibility for this specific behavior, not a new live lab run.

## Output contract and handling

| Upstream behavior | bhq handling |
|---|---|
| `<datetime>_<domain>_<type>.json`, also inside a ZIP | Both forms are tested |
| Envelope contains `data` and `meta` (`type`, `count`, `version`, `methods`, `collectorversion`) | Retains metadata per file; rejects mismatched type/count and invalid metadata value types |
| Writer sets schema version 6 and collectorversion `RustHound-CE v2.5.12` | Shows declared source; this is not an authenticity check |
| Writer sets `methods` to 0 for every mode | Warns that the collection command/logs are required to identify the mode |
| Writer omits empty collections | Missing core files remain an analysis limitation; absence alone does not prove a failed request |
| Users, groups, computers, domains use `Properties`, `Aces`, `Members`, and `ObjectIdentifier` | Fixtures check account queries, group membership, ACL edges, and replication grants combined through recorded membership |
| User/computer `AllowedToDelegate` contains target objects | Reads these separately from raw SPNs in `Properties.allowedtodelegate` |
| Checker replaces known target FQDNs with SIDs and retains unresolved identifiers | Resolves loaded targets to names; preserves unknown identifiers without inventing SPNs |
| Six additional AD CS collection types can be emitted | Loads all six; analyzes recorded template conditions, grants, publication and certificate/policy references; no automatic DA edge |

Source references:
[writer](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/json/maker/common.rs),
[shared structures](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/common.rs),
[user](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/user.rs),
[computer](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/computer.rs),
[group](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/group.rs),
[domain](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/domain.rs),
[target resolution](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/json/checker/common.rs).

## Collection limits that matter

- `LocalGroups` is declared but the reviewed collection pipeline leaves it empty.
  GPO-derived local groups are instead written to domain/OU `GPOChanges`, and
  GPO-derived user rights to computer `UserRights`. `policy` and `user-rights` expose these fields; conditional routes distinguish
  GPOChanges projections from direct local-group observations.
- Empty session structures default to `Collected: true`. An empty session result
  does not establish that the session module ran. `sessions` preserves populated results and collection state; consistent confirmed
  entries can contribute conditional routes, without proving interactive logon
  or usable credential material.
- In this version, `DCOnly` includes DC SYSVOL access; `LdapOnly` excludes it.
  Preserve the actual command and logs rather than interpreting `methods: 0` or
  assuming that all modes named DCOnly have identical behavior across collectors.
- `AllowedToAct` is exposed as recorded RBCD configuration, and `Trusts` as raw
  fields associated with the source domain. Trust traversal remains unmodeled. RBCD can contribute conditional host
  transitions; direct GPO ACLs can connect to candidate policy scope.
  `HasSIDHistory`, `UserRights`, populated sessions, and GPO-derived local groups
  remain unmodeled; notices are not a complete inventory of every unused field.

Source references:
[mode definitions](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/args.rs),
[module dispatch](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/modules/mod.rs),
[GPO mapping](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/modules/gpo/local_group.rs),
[session handling](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/modules/sessions/mod.rs).

RBCD fields follow the computer structure above. Trust fields follow the
[trust structure](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/trust.rs).
Additional synthetic cases in `tests/test_ad_coverage.py` exercise source-relative
trust fields, configured RBCD principals, policy ACLs and nested replication grants.

## Remaining validation

A lab collection should include the exact collector version, command with
credential values removed, logs, and original output kept outside this repo.
Check selected relationships against known lab configuration and, when useful,
BloodHound CE's interpretation of the same input. A real collection validates
those cases; it does not establish every collection method or environment.
