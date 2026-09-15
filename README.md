# bhq — offline BloodHound analyzer

Query BloodHound collector JSON from the terminal without running a database or
BloodHound GUI. `bhq` reads a directory of JSON files or a ZIP archive. It does not
collect from AD, authenticate to hosts, crack passwords, or execute the paths it
prints.

## Questions and commands

| Question | Command |
|---|---|
| What objects and recorded property clues are available? | `bhq objects` / `bhq object` / `bhq clues` |
| Which accounts have SPNs or do not require Kerberos pre-authentication? | `bhq kerberoast` / `bhq asrep` |
| What ACL and group-membership paths start at this principal? | `bhq path` / `bhq controls` |
| What local admin or remote-access relationships were collected? | `bhq local` |
| What delegation settings and replication rights were recorded? | `bhq deleg` / `bhq dcsync` |
| What trust configuration was recorded for each domain? | `bhq trusts` |
| Which ESC conditions are visible for this principal? | `bhq adcs --from <principal>` |
| Which principals can reach the configured high-value set? | `bhq reachers` |

Each command takes the collection path first. `report` combines these queries.
Results are leads for validation, not proof that an account can be compromised or
that a printed path can be executed.

Additional recorded data: `sessions`, `access`, `policy`, `sid-history`,
`user-rights`, and `adcs --from <principal>`. `coverage --raw-only` lists fields
without a dedicated query outlet. `route` joins conditional relationships with
separate account/object/host states and evidence per transition.
See [analysis and examples](docs/analysis.md).

## Install

Python 3.10 or newer is required. There are no runtime dependencies.

```sh
git clone https://github.com/soloclz/bhq.git
cd bhq
pipx install .
bhq --help
```

After updating this checkout with `git pull --ff-only`, run `pipx reinstall bhq`
to refresh the installed copy. A normal pipx install does not read subsequent
source edits automatically. If the command is not on PATH, run `pipx ensurepath`
and open a new terminal.

For development, use `uv sync --extra dev`, then `uv run pytest -q`. Without
installing, run `PYTHONPATH=src python3 -m bhq --help` from the checkout.

## Usage

```sh
bhq objects ./collection --kind gpo
bhq clues ./collection --kind user
bhq object ./collection "ALICE@TEST.LOCAL"
bhq report ./collection --from alice
bhq report ./collection --from alice --format md -o report.md
bhq report ./collection --format json -o report.json
bhq path ./collection.zip alice --goal da
bhq controls ./collection "SRVADMINS@TEST.LOCAL" -d 3
bhq members ./collection "DOMAIN ADMINS@TEST.LOCAL"
bhq local ./collection alice
bhq deleg ./collection
bhq trusts ./collection
bhq dcsync ./collection
bhq reachers ./collection
bhq adcs ./collection --from alice --format md -o adcs-alice.md
```

Keep each collection snapshot in a separate directory. Duplicate object IDs are
rejected, but non-overlapping snapshots cannot reliably be distinguished. Use a
qualified principal name or SID when a short name is ambiguous across domains.
All fixtures in `tests/` are synthetic; no engagement collection is included.

## Compatibility and validation

| Input | Current evidence |
|---|---|
| Legacy local-group fields (`LocalAdmins`, `RemoteDesktopUsers`, etc.) | Synthetic fixtures exercise loading and queries |
| CE `LocalGroups` layout | Synthetic fixtures exercise all four local-access mappings and failure reporting |
| SharpHound / bloodhound-python / bloodhound-ce-python | Intended input families; no version-pinned end-to-end compatibility matrix yet |
| RustHound-CE v2.5.12 | Source reviewed at a pinned commit; reduced synthetic fixtures exercise metadata, core queries, delegation targets, and unsupported-data warnings. Live collection remains unverified. See [details](docs/rusthound-ce.md). |

The loader uses filenames and object fields to select data. When `meta` is
present, its type and count must agree with the file; declared collector, schema,
and methods are retained in JSON reports and summarized in text/Markdown.
Unverified schema versions produce a warning. This is not complete schema
validation or proof of collection completeness. Users, groups, computers, domains, GPOs, OUs, containers and six AD CS object
types are loaded; other JSON filenames are reported as not analyzed. Empty or missing metadata does not identify the collector.

References: [BloodHound JSON formats](https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats),
[RustHound-CE](https://github.com/g0h4n/RustHound-CE).

## Interpretation limits

- **`path` uses ACL object-control and group-membership edges.** `route` is a
  separate conditional model that can join confirmed local-group observations,
  recorded sessions, resolved delegation/RBCD, SID-history grants and candidate
  policy effects. Every transition has source evidence and unmet requirements;
  computer-account control is distinct from host administration. Reports keep
  both results. Empty results do not establish the absence of a route.
- **A path is not an execution plan.** Object type, effective permissions,
  authentication requirements, and environmental preconditions are not evaluated
  for each edge. Rights such as `GenericWrite` do not mean the same operation is
  available on every target.
- **Delegation target objects are not SPNs.** `delegation.constrained[].to`
  retains raw `Properties.allowedtodelegate` values; `targets` separately reports
  `AllowedToDelegate` object IDs, names, types, and whether they resolve in the
  loaded collection. Target objects do not establish a service name or port.
  `delegation.rbcd` lists configured `AllowedToAct` principals for each target;
  it does not prove control of those principals. `route` can use this configuration
  as a conditional transition with explicit prerequisites.
- **Trust direction is relative to the source domain.** `trusts` preserves the
  collector's field names and values; false stays false and unrecorded fields
  display as null. A trust record does not verify connectivity, authentication,
  selective authentication, or permission to access resources across that trust.
- **The goal set is broader than Domain Admins.** It includes selected well-known
  RIDs, principals with recorded domain-control or replication rights, and the
  named group `DnsAdmins`. Reaching a goal does not prove Domain Admin membership
  or equivalent capability. `path`, `reachers`, and `report` default to the
  explicit `high-value` goal. Use `--goal da` for loaded Domain Admins groups
  identified by domain SID and RID 512. Reports include the selected goal and
  endpoint reason; an existing goal is a valid zero-hop path.
- **DCSync findings combine recorded grants per principal and domain.** Nested
  group membership and `PrimaryGroupSID` are included; cycles terminate without
  duplicating membership edges. Grants on different domains are never combined.
  `dcsync_findings` retains the domain, granting principals, and membership paths.
  Deny ACEs, token restrictions, and missing membership data are not evaluated;
  these findings are not a live effective-access check.
- **Local-access counts are evidence summaries.** `attempted` counts records
  marked `Collected`; `answered` counts records with members. Neither is a
  packet-level observation. Missing records, explicit failures, and empty
  results require different interpretation; an empty result without a failure
  reason can remain ambiguous. Group membership does not prove a successful
  RDP, WinRM, DCOM, or administrative login.

Reports include collection warnings and a machine-readable analysis scope.
These limitations also apply when a report contains no runtime warnings.

## Objects and property clues

`objects` lists identifiers and names; `--kind` limits the object type and
`--match` filters names or IDs by substring. `object` returns one complete raw
record as JSON, with its source filename. If a group and OU share a name, use
an ObjectIdentifier; principal-only commands retain their existing name lookup.

`clues` selects nonempty description/info, home/script/profile paths and password
attributes, plus selected flags (passwordnotreqd, trustedtoauth, admincount,
haslaps, and enabled=false). It does not verify credentials or infer that a flag
proves exploitability. Fields not selected remain available through `object`.
Text/Markdown reports show the first five clue objects with a displayed count;
`clues` and JSON reports retain all selected entries.

## Contributing

Use synthetic fixtures when reporting a bug. Include the collector version,
collection methods, relevant JSON shape, expected result, and observed result.
Do not submit real collections, credentials, or engagement reports.

`src/bhq/loader.py` normalizes input, `queries.py` performs analysis, and
`report.py` / `cli.py` present results. Keep collection failures distinguishable
from negative findings when adding support for a collector or relationship.

## License

MIT. See [LICENSE](LICENSE).

## Output additions in 0.3

Reports add `extended` (sessions, access, SID history, user rights, policy, AD CS,
field coverage) and, when a starting principal resolves, `candidate_route`.
The 0.2 `path` result remains separate and unchanged in scope. New CLI commands
accept `--format json`; no schema conversion or network service is required.
See [conditional model and limits](docs/analysis.md).

## Output changes in 0.2

JSON reports replace the misleading `path_to_da` key with `path` and add `goal`.
The Python `path_to_da()` helper now means Domain Admins specifically; use
`path_to_goal()` for the default high-value target set. Reports add domain-scoped
`dcsync_findings`, `property_clues`, `delegation.rbcd`, and `trusts`. Existing
`dcsync` name lists remain, but domain identity and grant provenance are in
`dcsync_findings`.

## Remaining coverage gaps

| Area | What is still required |
|---|---|
| Local access and sessions | Conditional routes now join recorded relationships; verify current effective access, logon type and credential availability |
| GPO effects | Candidate scope handles recorded containment and inheritance; filtering, enabled state, precedence and actual application still require confirmation |
| AD CS | ESC1–ESC17 are listed, but some require data outside BloodHound; certificate-chain validation and live CA behavior remain separate checks |
| Shares, SYSVOL file contents, services and live authentication | Separate protocol-specific enumeration and verification |
| Full collector compatibility | Real lab output and comparisons with known configuration; synthetic fixtures cover selected cases only |
