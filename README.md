# bhq — offline BloodHound analyzer

Query BloodHound collector JSON from the terminal without running a database or
BloodHound GUI. `bhq` reads a directory of JSON files or a ZIP archive. It does not
collect from AD, authenticate to hosts, crack passwords, or execute the paths it
prints.

## Questions and commands

| Question | Command |
|---|---|
| Which accounts have SPNs or do not require Kerberos pre-authentication? | `bhq kerberoast` / `bhq asrep` |
| What ACL and group-membership paths start at this principal? | `bhq path` / `bhq controls` |
| What local admin or remote-access relationships were collected? | `bhq local` |
| What delegation settings and replication rights were recorded? | `bhq deleg` / `bhq dcsync` |
| Which principals can reach the configured high-value set? | `bhq reachers` |

Each command takes the collection path first. `report` combines these queries.
Results are leads for validation, not proof that an account can be compromised or
that a printed path can be executed.

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
bhq report ./collection --from alice
bhq report ./collection --from alice --format md -o report.md
bhq report ./collection --format json -o report.json
bhq path ./collection.zip alice --goal da
bhq controls ./collection "SRVADMINS@TEST.LOCAL" -d 3
bhq members ./collection "DOMAIN ADMINS@TEST.LOCAL"
bhq local ./collection alice
bhq deleg ./collection
bhq dcsync ./collection
bhq reachers ./collection
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
validation or proof of collection completeness. Only users, groups, computers,
domains, GPOs, OUs, and containers are loaded; other JSON filenames are reported
as not analyzed. Empty or missing metadata does not identify the collector.

References: [BloodHound JSON formats](https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats),
[RustHound-CE](https://github.com/g0h4n/RustHound-CE).

## Interpretation limits

- **Paths use ACL object-control and group-membership edges.** Local access and
  delegation are reported separately. Trust traversal, GPO links and OU
  inheritance, AD CS paths, interactive sessions, and Entra/hybrid identity are
  not modeled. An empty result does not establish that no attack path exists.
- **A path is not an execution plan.** Object type, effective permissions,
  authentication requirements, and environmental preconditions are not evaluated
  for each edge. Rights such as `GenericWrite` do not mean the same operation is
  available on every target.
- **Delegation target objects are not SPNs.** `delegation.constrained[].to`
  retains raw `Properties.allowedtodelegate` values; `targets` separately reports
  `AllowedToDelegate` object IDs, names, types, and whether they resolve in the
  loaded collection. Target objects do not establish a service name or port.
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

## Contributing

Use synthetic fixtures when reporting a bug. Include the collector version,
collection methods, relevant JSON shape, expected result, and observed result.
Do not submit real collections, credentials, or engagement reports.

`src/bhq/loader.py` normalizes input, `queries.py` performs analysis, and
`report.py` / `cli.py` present results. Keep collection failures distinguishable
from negative findings when adding support for a collector or relationship.

## License

MIT. See [LICENSE](LICENSE).

## Output changes in 0.2

JSON reports replace the misleading `path_to_da` key with `path` and add `goal`.
The Python `path_to_da()` helper now means Domain Admins specifically; use
`path_to_goal()` for the default high-value target set.
