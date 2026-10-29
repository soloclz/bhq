# bhq — offline BloodHound analyzer

`bhq` reads BloodHound collector JSON from a directory or ZIP archive and shows
recorded AD objects, relationships, and investigation leads without a database or
GUI. It does not connect to AD or execute the paths it finds.

## Install

Requires Python 3.10 or newer. There are no runtime dependencies.

```sh
git clone https://github.com/soloclz/bhq.git
cd bhq
pipx install .
bhq --help
```

After updating the checkout, run `pipx reinstall bhq` to refresh the installed
command.

## Quick start

Put one collection snapshot under `collections/`, which Git ignores. Replace
`lab` and the example principal with your collection and account. All test
fixtures in this repository are synthetic.

```sh
mkdir -p reports
bhq report ./collections/lab --format md -o reports/report.md
bhq objects ./collections/lab --kind user
bhq path ./collections/lab "ALICE@TEST.LOCAL" --goal da
```

`report` selects findings for review; use `--format json` for structured results.
Generated files under `reports/` are ignored by Git.

## Commands

| Question | Commands |
|---|---|
| What objects, properties, and fields were recorded? | `objects`, `object`, `clues`, `coverage` |
| What account leads and group members were recorded? | `kerberoast`, `asrep`, `members` |
| What can a principal control or reach? | `path`, `controls`, `reachers`, `route` |
| What AD configuration and grants were recorded? | `deleg`, `dcsync`, `trusts`, `adcs` |
| What host access, sessions, and policy data were recorded? | `local`, `access`, `sessions`, `policy`, `user-rights`, `sid-history` |

Each command takes the collection path first. Run `bhq <command> --help` for its
options. Use a qualified name or SID when a short name matches more than one
object.

## Read the results

`path` follows recorded ACL and group-membership relationships; `route` joins
conditional account, object, and host transitions. Neither establishes current
effective access. `path` and `reachers` default to the `high-value` goal;
`route` defaults to `da`. Specify `--goal` when the distinction matters.

See [analysis and interpretation](docs/analysis.md) for report fields, evidence,
and limits. [RustHound-CE compatibility](docs/rusthound-ce.md) records the reviewed
versions and validation. SharpHound, bloodhound-python, and
bloodhound-ce-python are intended input families without a version-pinned
end-to-end compatibility check.

## Contributing

For bugs, use synthetic fixtures and include the collector version, collection
methods, relevant JSON shape, expected result, and observed result. Do not
submit real collections, credentials, or engagement reports. For development,
run `uv sync --extra dev` and `uv run pytest -q`.

## License

MIT. See [LICENSE](LICENSE).
