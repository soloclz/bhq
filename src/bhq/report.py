"""One-shot report — the four AD-analysis questions in one pass, optionally
anchored on a foothold principal (`--from`).

`build()` produces a structured dict; `as_text` / `as_md` / `as_json` render it.
Markdown/JSON are for dropping into `evidence/` and the engagement report; text
is the terminal default.
"""

from __future__ import annotations

import json

from . import queries
from .loader import Graph


def build(g: Graph, start_name: str | None = None) -> dict:
    data: dict = {
        "collection": queries.coverage(g),
        "analysis": {
            "scope": queries.ANALYSIS_SCOPE,
            "warnings": queries.diagnostics(g),
        },
        "kerberoastable": queries.kerberoastable(g),
        "asreproastable": [a["name"] for a in queries.asreproastable(g)],
        "delegation": queries.delegation(g),
        "dcsync": queries.dcsync_principals(g),
        "high_value_groups": [
            {"group": grp, "members": members, "why": why}
            for grp, members, why in queries.high_value_members(g)
        ],
        "reachers": [
            {"name": g.name(sid), "hops": hops,
             "path": [{"name": n, "via": via} for n, via in chain]}
            for sid, (hops, chain) in sorted(
                queries.who_can_reach_high_value(g).items(), key=lambda kv: (kv[1][0], g.name(kv[0])))
        ],
        "from": start_name,
    }
    if start_name:
        sid = g.sid_of(start_name)
        if not sid:
            candidates = g.sid_candidates(start_name)
            if candidates:
                choices = ", ".join(f"{g.qualified_name(s)} [{s}]" for s in sorted(candidates))
                data["error"] = f"principal is ambiguous: {start_name}; use a qualified name or SID ({choices})"
            else:
                data["error"] = f"principal not found: {start_name}"
            return data
        path, goals = queries.path_to_da(g, sid)
        data["path_to_da"] = {
            "goals": goals,
            "path": [{"name": g.name(s), "kind": g.kind(s), "via": lbl} for s, lbl in path] if path else None,
        }
        data["controls"] = [
            {"depth": d, "from": frm, "edge": e, "to": to}
            for d, frm, e, to in queries.controls(g, sid, max_depth=2)
        ]
        data["local"] = [{"computer": n, "right": r} for n, r in queries.local_admin_of(g, sid)]
    return data


def _coverage_line(c: dict) -> str:
    return f"users={c['users']}  groups={c['groups']}  computers={c['computers']}"


def _local_coverage_line(c: dict) -> str:
    counts = "  ".join(
        f"{label}={value['attempted']}/{value['answered']}"
        for label, value in c["local_collections"].items()
    )
    return f"local groups attempted/answered of {c['computers']}:  {counts}"


def as_text(data: dict) -> str:
    c = data["collection"]
    L = ["== collection ==", _coverage_line(c)]
    if c["computers"]:
        L.append(_local_coverage_line(c))
    warnings = data["analysis"]["warnings"]
    L.append("\n== analysis confidence ==")
    if warnings:
        L.extend(f"  ! {warning}" for warning in warnings)
    else:
        L.append("  collection has the core object types; path scope limits still apply")
    excluded = ", ".join(data["analysis"]["scope"]["not_modeled"])
    L.append(f"  path model: ACL control + group membership; not modeled: {excluded}")
    L.append("\n== Q1 offline-crackable ==")
    L.append(f"Kerberoastable ({len(data['kerberoastable'])}):")
    for k in data["kerberoastable"]:
        L.append(f"  {k['name']}  {','.join(k['spns'])}" + ("  [admincount]" if k["admincount"] else ""))
    L.append("AS-REP roastable: " + (", ".join(data["asreproastable"]) or "(none)"))
    L.append("\n== Q4 special rights ==")
    L.append("Unconstrained delegation: " + (", ".join(data["delegation"]["unconstrained"]) or "(none)"))
    for cd in data["delegation"]["constrained"]:
        L.append(f"Constrained delegation: {cd['name']} -> {', '.join(cd['to'])}")
    L.append("DCSync-capable: " + (", ".join(data["dcsync"]) or "(none)"))
    L.append("\n== high-value groups (derived, not a name list) ==")
    for hv in data["high_value_groups"]:
        if hv["members"]:
            L.append(f"{hv['group']} [{hv['why']}] ({len(hv['members'])}): {', '.join(hv['members'])}")
        elif hv["why"] == "well-known-admin-rid":
            L.append(f"{hv['group']} [{hv['why']}] (0)")     # built-in and empty is the normal state
        else:
            # Granted a dangerous right *and* empty: membership audits see nothing
            # while the right stays live. Whoever can write `member` becomes it.
            L.append(f"{hv['group']} [{hv['why']}] (0 — privilege granted but no members; "
                     f"invisible to membership audits, live to anyone who can write `member`)")
    r = data["reachers"]
    L.append(f"\n== who can reach admin-equivalence ({len(r)}) ==")
    if not r:
        L.append("  (nobody outside the high-value set)")
    for row in r:
        arrows = " ".join(
            (f"{h['name']} --{h['via']}-->" if h["via"] else h["name"]) for h in row["path"])
        L.append(f"  {row['name']} ({row['hops']} hop{'s' if row['hops'] != 1 else ''}): {arrows}")
    if data.get("from"):
        L.append(f"\n== Q2 from '{data['from']}' ==")
        if data.get("error"):
            L.append(f"  ! {data['error']}")
            return "\n".join(L)
        p = data["path_to_da"]
        L.append(f"Shortest path to admin-equivalence ({len(p['goals'])} goals) "
                 f"— the last hop names which one:")
        if p["path"]:
            for hop in p["path"]:
                via = f"  --{hop['via']}-->" if hop["via"] else ""
                L.append(f"  {via} {hop['name']} [{hop['kind']}]")
        else:
            L.append("  (no ACL/membership path — likely needs a local-admin hop; see Q3)")
        L.append("Outbound control (<=2 hops):")
        for r in data["controls"] or []:
            L.append(f"  {'  ' * r['depth']}{r['from']} --{r['edge']}--> {r['to']}")
        if not data["controls"]:
            L.append("  (none)")
        L.append("Q3 local admin/remote: " + (", ".join(f"{r['computer']}({r['right']})" for r in data["local"]) or "(none collected)"))
    return "\n".join(L)


def as_md(data: dict) -> str:
    c = data["collection"]
    L = ["# BloodHound offline analysis", "", "## Collection", "", f"`{_coverage_line(c)}`"]
    if c["computers"]:
        L += ["", f"`{_local_coverage_line(c)}`"]
    L += ["", "## Analysis confidence", ""]
    warnings = data["analysis"]["warnings"]
    if warnings:
        L.extend(f"> ⚠ {warning}" for warning in warnings)
    else:
        L.append("Core object types are present; the path-scope limits below still apply.")
    excluded = ", ".join(data["analysis"]["scope"]["not_modeled"])
    L += ["", f"**Path model:** ACL control + group membership. **Not modeled:** {excluded}."]
    L += ["", "## Q1 — offline-crackable", "", f"**Kerberoastable ({len(data['kerberoastable'])})**", "",
          "| account | SPN | admincount |", "|---|---|---|"]
    for k in data["kerberoastable"]:
        L.append(f"| `{k['name']}` | `{','.join(k['spns'])}` | {'yes' if k['admincount'] else ''} |")
    L += ["", f"**AS-REP roastable:** {', '.join('`%s`' % a for a in data['asreproastable']) or '(none)'}"]
    L += ["", "## Q4 — special rights", "",
          f"- **Unconstrained delegation:** {', '.join('`%s`' % x for x in data['delegation']['unconstrained']) or '(none)'}"]
    for cd in data["delegation"]["constrained"]:
        L.append(f"- **Constrained delegation:** `{cd['name']}` → {', '.join(cd['to'])}")
    L.append(f"- **DCSync-capable:** {', '.join('`%s`' % x for x in data['dcsync']) or '(none)'}")
    L += ["", "## High-value groups (derived, not a name list)", "",
          "| group | why | members |", "|---|---|---|"]
    for hv in data["high_value_groups"]:
        members = ", ".join("`%s`" % m for m in hv["members"])
        if not members:
            members = ("_(none)_" if hv["why"] == "well-known-admin-rid"
                       else "_(none — privilege live but invisible to membership audits)_")
        L.append(f"| `{hv['group']}` | {hv['why']} | {members} |")
    L += ["", f"## Who can reach admin-equivalence ({len(data['reachers'])})", ""]
    if not data["reachers"]:
        L.append("_(nobody outside the high-value set)_")
    for row in data["reachers"]:
        arrows = " ".join(
            (f"`{h['name']}` —{h['via']}→" if h["via"] else f"`{h['name']}`") for h in row["path"])
        hops = f"{row['hops']} hop" + ("s" if row["hops"] != 1 else "")
        L.append(f"- **{row['name']}** ({hops}): {arrows}")
    if data.get("from"):
        L += ["", f"## Q2 — from `{data['from']}`"]
        if data.get("error"):
            L.append(f"> {data['error']}")
            return "\n".join(L)
        p = data["path_to_da"]
        L += ["", f"**Shortest path to admin-equivalence** ({len(p['goals'])} goals; "
              f"the last hop names which one):", ""]
        if p["path"]:
            parts = [
                (f"—{h['via']}→ `{h['name']}`" if h["via"] else f"`{h['name']}`")
                for h in p["path"]
            ]
            L.append("> " + " ".join(parts))
        else:
            L.append("> (no ACL/membership path — likely needs a local-admin hop; see Q3)")
        L += ["", "**Outbound control (≤2 hops):**", ""]
        if data["controls"]:
            for r in data["controls"]:
                L.append(f"- {'  ' * r['depth']}`{r['from']}` —{r['edge']}→ `{r['to']}`")
        else:
            L.append("- (none)")
        L += ["", "**Q3 local admin/remote:** " + (", ".join(f"`{r['computer']}` ({r['right']})" for r in data["local"]) or "(none collected)")]
    return "\n".join(L) + "\n"


def as_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


RENDERERS = {"text": as_text, "md": as_md, "json": as_json}


def render(g: Graph, start_name: str | None = None, fmt: str = "text") -> str:
    return RENDERERS[fmt](build(g, start_name))
