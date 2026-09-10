# RustHound-CE v2.5.12 compatibility

Status: source review and reduced synthetic fixtures. No live AD collection,
upstream serializer execution, or BloodHound CE ingestion comparison has been
performed. This page describes the reviewed version only.

Upstream tag: `v2.5.12`.
Commit: `aeb28db95f0149a1579c2517536083e150ae2803`.
Fixtures: [`tests/test_rusthound.py`](../tests/test_rusthound.py). All names and
identifiers are invented. They are handwritten excerpts of relevant fields,
not complete collector documents or a copied engagement collection.

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
| Six additional AD CS collection types can be emitted | Lists their filenames as not analyzed; does not build AD CS paths |

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
  GPO-derived user rights to computer `UserRights`. bhq warns when these fields
  contain relationships; it does not treat them as direct local-group observations.
- Empty session structures default to `Collected: true`. An empty session result
  does not establish that the session module ran. Populated session results are
  flagged as not analyzed; sessions are not added to the path graph.
- In this version, `DCOnly` includes DC SYSVOL access; `LdapOnly` excludes it.
  Preserve the actual command and logs rather than interpreting `methods: 0` or
  assuming that all modes named DCOnly have identical behavior across collectors.
- `AllowedToAct` is exposed as recorded RBCD configuration, and `Trusts` as raw
  fields associated with the source domain. Neither contributes path edges.
  Direct GPO/OU/container ACLs are loaded, but policy effects are not derived.
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
