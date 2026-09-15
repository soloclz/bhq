# Recorded data and conditional analysis (bhq 0.3)

bhq is an offline analyzer. These commands read a saved collection; they do not
connect to hosts, authenticate, change AD objects, or execute the routes shown.
The implementation is organized under `src/bhq/analysis/`, separately from the
legacy ACL/membership queries and report presentation.

## Start with the report, then query the relevant evidence

```sh
bhq report ./collection --from alice --goal da
bhq sessions ./collection
bhq access ./collection
bhq policy ./collection
bhq adcs ./collection --from alice
bhq sid-history ./collection
bhq user-rights ./collection
bhq coverage ./collection --raw-only
bhq route ./collection alice --goal da
bhq route ./collection alice --to WS01.TEST.LOCAL --state host
```

New commands accept `--format json` for complete records and source references.
The report includes a compact overview and, with `--from`, a conditional route
alongside the original `path` result. Its JSON includes complete `extended`
analysis and `candidate_route`; the existing `path` key and semantics remain.
`bhq object` also works on all six AD CS object types.

| Command | Analysis | What the result does not establish |
|---|---|---|
| `sessions` | Per-computer Sessions, PrivilegedSessions and RegistrySessions; method, collection status, failure and original entries | Interactive logon, continued presence, or available credential material |
| `access` | Local-group members with provenance and collection status, including unknown local group RIDs | Effective logon access, host reachability or absence of deny rights |
| `sid-history` | Both HasSIDHistory and Properties.sidhistory; historical identifiers retain their sources | Knowledge of the historical account credential or its current group memberships |
| `user-rights` | Privilege assignments, deny-right names, unresolved LocalNames and failures | Effective token rights or a host-administration capability |
| `policy` | Links, containment, inheritance blocking/enforcement and explicit GPOChanges projections | Resultant policy, link enablement, WMI/security filtering, precedence or SYSVOL write access |
| `adcs --from` | ESC1–ESC17 matrix; template/CA conditions; publication; selected-subject grants through recorded membership; NTAuth and chain-reference joins | Successful enrollment/authentication, verified certificate chains, or prerequisites outside the collection |
| `coverage` | Every observed field path, its query outlet, source examples and unhandled JSON files | Upstream collection completeness or complete semantic interpretation of every field |

`raw-only` means there is no dedicated query outlet for that field shape. The
original field remains available through `object`. `query-outlet` means a known
field has an outlet; it does not mean every constraint needed for effective access
is evaluated. Unknown nested fields are listed even inside familiar objects. Unhandled ACE
RightName values are also listed with their source; a familiar Aces shape does
not hide an unmodeled relationship.

## Conditional route states

`path` retains the legacy ACL/membership graph. `route` uses a separate state graph:

- `principal`: control/use of an account, or membership represented by a group.
- `object`: ability to affect a directory object; this does not imply host access.
- `host`: conditional administrative access to the computer's operating system.
- `remote`: conditional remote access, without assuming administrative access.
- `sid`: a historical SID used for grants, without the historical account credential.

A synthetic example:

```text
Alice [principal] --AdminTo--> WS01 [host]
WS01 [host] --HasSession--> Bob [principal]
Bob [principal] --MemberOf--> Domain Admins [principal]
```

Each transition carries `evidence` and `requires`. The HasSession transition needs
current session/credential availability and access despite host protections.
A CanRDP transition ends in `remote` and cannot continue through HasSession.
GenericAll on a computer account can lead to a `principal` state, not directly to
`host`. SID history does not inherit the historical account's current memberships.
This prevents those distinct facts from being silently equated.

RBCD and resolved constrained-delegation targets can contribute conditional host
transitions, with explicit account, impersonated-identity, service and KDC
requirements. Raw SPNs and unresolved target names remain available in `deleg`;
there is no guessed host edge. GPO scope produces candidate transitions only for
loaded GPOs with no recorded inheritance block or unknown inheritance status.
Explicit GPOChanges projections are labeled separately from observed local groups.

Deleted objects and missing endpoints do not contribute transitions. Session
entries with mismatched computers, failed/partial collection, or unresolved users
do not contribute transitions either. Observations remain queryable even when
excluded from the graph. An empty result is `no-modeled-route`, not proof that no
route exists. The shortest result is not ranked by reliability, effort or success.

## AD CS interpretation

All six RustHound-CE AD CS types are loaded: enterprisecas, rootcas, aiacas,
ntauthstores, certtemplates and issuancepolicies. An AD CS-only collection is valid
input. IDs and source files survive directory and ZIP loading.

`adcs` always prints ESC1–ESC17 so a missing detector cannot look like a negative
finding. The summary states are:

- `candidate`: the selected subject and recorded data meet the modeled conditions.
- `configuration-candidate`: relevant CA settings were recorded, but live issuance
  behavior is not established by the collection.
- `not-matched`: at least one recorded condition is false.
- `unknown`: a modeled condition is missing or ambiguous.
- `not-observable`: the required source is outside the loaded BloodHound data.

ESC1 checks require a published template, selected-subject template and CA Enroll
grants, authenticationenabled=true, enrolleesuppliessubject=true,
requiresmanagerapproval=false and an integer authorizedsignatures=0. Missing or
ill-typed values are unknown, not false. The same publication, enrollment and
approval gates are reused where applicable for ESC2, ESC3, ESC9, ESC13, ESC15 and
ESC17. ESC4 and ESC5 report selected-subject object-control candidates; directory
control of a CA object is not treated as a CA service role.

With `--from`, template grants are matched against the selected principal and
recorded nested/primary-group membership. CA enrollment requires an explicit
Enroll entry in confirmed CARegistryData.CASecurity.Data. GenericAll on the CA
*directory object* is not treated as the CA service enrollment grant. AutoEnroll
alone is not treated as Enroll. Without a selected subject the tool lists grants
but does not combine unrelated principals' permissions.

Reported properties may be collector defaults. In particular, the reviewed
RustHound-CE source can construct CARegistryData defaults and derive CASecurity
from a directory security descriptor: `Collected: true` is not independent proof
of a successful CA-server registry query. Inspect the collection mode and logs.
No deny-ACE or effective-token evaluation is performed.

Template analysis covers unrestricted/Any Purpose EKUs, enrollment-agent usage,
SID-extension settings, issuance-policy group links, schema version and client or
server authentication usage. CA analysis covers SAN settings, CA roles and HTTP
endpoint results when their collection status is explicit. CA certificate-chain
thumbprints and NTAuth thumbprints are matched to recorded objects, without
cryptographic validation or assuming that every loaded domain shares a forest.
These outputs support follow-up analysis; they do not create a DA edge.

CA registry data and HTTP enrollment results are retained in JSON. Inspect their
Collected/FailureReason fields before interpreting values. The reviewed
RustHound-CE v2.5.12 output does not provide the CA `DisableExtensionList` or RPC
encryption setting used to assess ESC16 and ESC11, so those rows are
`not-observable` unless a compatible collector records the fields. ESC10, ESC12
and ESC14 also need host, key-store or attribute-specific evidence outside generic
BloodHound JSON. Certipy remains useful for live CA behavior and these missing
sources. `not-observable` never means safe.

## Validation and references

Tests use synthetic fixtures with positive and negative controls. They check
source provenance, status contradictions, missing/invalid fields, nested groups,
route-state separation, inheritance blocking, CA/template grant separation,
unresolved references and new nested fields. No real AD collection, upstream
serializer execution or BloodHound CE ingestion comparison has been performed.

Reviewed collector: RustHound-CE v2.5.12,
`aeb28db95f0149a1579c2517536083e150ae2803`.

- [RustHound shared structures](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/common.rs)
- [Computer and session fields](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/computer.rs)
- [Template fields](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/certtemplate.rs)
- [CA fields and collection defaults](https://github.com/g0h4n/RustHound-CE/blob/aeb28db95f0149a1579c2517536083e150ae2803/src/objects/enterpriseca.rs)
- [HasSession requirements](https://bloodhound.specterops.io/resources/edges/has-session)
- [HasSIDHistory semantics](https://bloodhound.specterops.io/resources/edges/has-sid-history)
- [GPO link and enforcement](https://bloodhound.specterops.io/resources/edges/gp-link)
- [Constrained delegation](https://bloodhound.specterops.io/resources/edges/allowed-to-delegate)
- [RBCD](https://bloodhound.specterops.io/resources/edges/allowed-to-act)
- [ADCSESC1 requirements](https://bloodhound.specterops.io/resources/edges/adcs-esc1)
- [Certipy 5.1.0 ESC detector source](https://github.com/ly4k/Certipy/blob/5.1.0/certipy/commands/find.py)
