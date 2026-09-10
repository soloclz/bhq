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
bhq path ./collection.zip alice
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
| RustHound-CE | Planned primary collector; real output compatibility has not yet been verified |

The loader uses filenames and object fields, not `meta.version`, to select data.
It does not validate the complete upstream schema. Successfully reading a ZIP
does not establish complete collector support. Only users, groups, computers,
domains, GPOs, OUs, and containers are loaded; other file types are not analyzed.

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
- **The goal set is broader than Domain Admins.** It includes selected well-known
  RIDs, principals with recorded domain-control or replication rights, and the
  named group `DnsAdmins`. Reaching a goal does not prove Domain Admin membership
  or equivalent capability. The `path_to_da` JSON key and some CLI labels retain
  their historical names; inspect the actual endpoint and reason.
- **DCSync findings combine directly recorded rights only for the same principal
  on the same domain object.** Rights on different domains are never combined.
  Rights distributed across a user's groups are not aggregated into effective
  permissions. The current name list means a match on at least one domain, not
  on every domain in the collection.
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
