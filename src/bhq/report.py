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
from .analysis import observations, policy, pki, routes, inventory, presentation


def build(g: Graph, start_name: str | None = None, goal: str = "high-value") -> dict:
    data: dict = {
        "goal": goal,
        "collection": queries.coverage(g),
        "analysis": {
            "scope": queries.ANALYSIS_SCOPE,
            "warnings": queries.diagnostics(g),
        },
        "property_clues": queries.property_clues(g),
        "kerberoastable": queries.kerberoastable(g),
        "asreproastable": [a["name"] for a in queries.asreproastable(g)],
        "delegation": queries.delegation(g),
        "trusts": queries.trusts(g),
        "dcsync": queries.dcsync_principals(g),
        "dcsync_findings": queries.dcsync_findings(g),
        "high_value_groups": [
            {"group": grp, "members": members, "why": why}
            for grp, members, why in queries.high_value_members(g)
        ],
        "reachers": [
            {"name": g.name(sid), "hops": hops,
             "path": [{"name": n, "via": via} for n, via in chain]}
            for sid, (hops, chain) in sorted(
                queries.who_can_reach_high_value(g, goal).items(), key=lambda kv: (kv[1][0], g.name(kv[0])))
        ],
        "from": start_name,
        "extended": {
            "access": observations.local_access(g), "sessions": observations.sessions(g), "sid-history": observations.sid_history(g),
            "user-rights": observations.user_rights(g), "policy": policy.policy(g),
            "adcs": pki.adcs(g), "coverage": inventory.inventory(g),
        },
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
        data['extended']['adcs'] = pki.adcs(g, sid)
        data['candidate_route'] = routes.route(g, sid, set(queries.goal_sids(g, goal)))
        path, goals = queries.path_to_goal(g, sid, goal)
        data["path"] = {
            "goals": goals,
            "endpoint_reason": queries.goal_sids(g, goal).get(path[-1][0]) if path else None,
            "path": [{"name": g.name(s), "kind": g.kind(s), "via": lbl} for s, lbl in path] if path else None,
        }
        data["controls"] = [
            {"depth": d, "from": frm, "edge": e, "to": to}
            for d, frm, e, to in queries.controls(g, sid, max_depth=2)
        ]
        data["local"] = [{"computer": n, "right": r} for n, r in queries.local_admin_of(g, sid)]
    return data


def _extended_lines(data):
    ext = data.get('extended', {})
    if not ext:
        return []
    pol, pki_data = ext['policy'], ext['adcs']
    raw = sum(r['status'] == 'raw-only' for r in ext['coverage']['fields'])
    lines = ['', 'Additional recorded data (full details: named command or JSON report):',
             f"- sessions: {sum(len(r['entries']) for r in ext['sessions'])} entries across {len(ext['sessions'])} method records",
             f"- sid-history: {len(ext['sid-history'])} entries; user-rights: {len(ext['user-rights'])} assignments",
             f"- policy: {len(pol['links'])} links, {len(pol['effects'])} scope results, {len(pol['changes'])} projected group records, {len(pol['issues'])} issues",
             f"- adcs: {len(pki_data['cas'])} enterprise CAs, {len(pki_data['templates'])} templates, {len(pki_data['publications'])} publication records",
             f"- coverage: {raw} raw-only field paths, {len(ext['coverage']['unmodeled_ace_rights'])} unmodeled ACE entries; use bhq coverage <collection> --raw-only"]
    if 'candidate_route' in data:
        lines += ['', 'Conditional route (account/object/host states):']
        lines += presentation.lines('route', data['candidate_route'])
    return lines


def _coverage_line(c: dict) -> str:
    return f"users={c['users']}  groups={c['groups']}  computers={c['computers']}"


def property_clue(row: dict) -> str:
    return (f"{row['kind']} {row['name']} [{row['id']}] "
            f"{json.dumps(row['properties'], ensure_ascii=False)} (source: {row['source_file']})")


def rbcd_finding(row: dict) -> str:
    principals = ", ".join(
        f"{p['name']} [{p['id']}]" + ("" if p["resolved"] else " [not in collection]")
        for p in row["principals"])
    return f"AllowedToAct on {row['target']} [{row['target_id']}]: {principals}"


def trust_finding(row: dict) -> str:
    trust = row["trust"]
    fields = ("TargetDomainName", "TargetDomainSid", "TrustDirection", "TrustType",
              "IsTransitive", "SidFilteringEnabled", "TrustAttributes")
    return (f"source={row['source']} [{row['source_id']}]; " + "; ".join(
        f"{field}={json.dumps(trust.get(field), ensure_ascii=False)}" for field in fields))


def dcsync_finding(row: dict) -> str:
    grants = "; ".join(f"{grant['granted_to']}:{grant['right']}" for grant in row["grants"])
    return f"{row['principal']} -> {row['domain']}; grants: {grants}"


def delegation_targets(row: dict) -> str:
    parts = []
    if row["to"]:
        parts.append("SPNs: " + ", ".join(row["to"]))
    if row.get("targets"):
        parts.append("target objects: " + ", ".join(
            f"{t['name']} [{t['id']}]" if t["resolved"] else f"{t['id']} [not in collection]"
            for t in row["targets"]))
    return "; ".join(parts)


def _collector_lines(c: dict) -> list[str]:
    declarations = {
        (m.get("collectorversion", "unknown"), str(m.get("version", "unknown")),
         str(m.get("methods", "unknown"))) for m in c.get("metadata", {}).values()
    }
    return [f"input declares: {collector}; schema={version}; methods={methods}"
            for collector, version, methods in sorted(declarations)]


def _local_coverage_line(c: dict) -> str:
    counts = "  ".join(
        f"{label}={value['attempted']}/{value['answered']}"
        for label, value in c["local_collections"].items()
    )
    return f"local groups attempted/answered of {c['computers']}:  {counts}"


def as_text(data: dict) -> str:
    c = data["collection"]
    L = ["== collection ==", _coverage_line(c)]
    L.extend(_collector_lines(c))
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
    clues = data["property_clues"]
    L.append(f"\n== recorded property clues (showing {min(5, len(clues))}/{len(clues)}) ==")
    L.extend(property_clue(row) for row in clues[:5])
    if len(clues) > 5:
        L.append("Use bhq clues <collection> for all selected properties; these are not verified credentials.")
    L.append("\n== Q1 offline-crackable ==")
    L.append(f"Kerberoastable ({len(data['kerberoastable'])}):")
    for k in data["kerberoastable"]:
        L.append(f"  {k['name']}  {','.join(k['spns'])}" + ("  [admincount]" if k["admincount"] else ""))
    L.append("AS-REP roastable: " + (", ".join(data["asreproastable"]) or "(none)"))
    L.append("\n== Q4 special rights ==")
    L.append("Unconstrained delegation: " + (", ".join(data["delegation"]["unconstrained"]) or "(none)"))
    for cd in data["delegation"]["constrained"]:
        L.append(f"Constrained delegation: {cd['name']} -> {delegation_targets(cd)}")
    L.append("Recorded RBCD configuration (not an executable path):")
    L.extend("  " + rbcd_finding(row) for row in data["delegation"]["rbcd"])
    if not data["delegation"]["rbcd"]:
        L.append("  (no populated AllowedToAct in loaded computers)")
    L.append("Recorded trusts (direction is relative to source; null means not recorded):")
    L.extend("  " + trust_finding(row) for row in data["trusts"])
    if not data["trusts"]:
        L.append("  (no trust entries in loaded domains; collection scope still applies)")
    L.append("Recorded DCSync rights:")
    L.extend("  " + dcsync_finding(row) for row in data["dcsync_findings"])
    if not data["dcsync_findings"]:
        L.append("  (no matching recorded grant combination)")
    L.append("\n== high-value groups (derived, not a name list) ==")
    for hv in data["high_value_groups"]:
        if hv["members"]:
            L.append(f"{hv['group']} [{hv['why']}] ({len(hv['members'])}): {', '.join(hv['members'])}")
        elif hv["why"] == "well-known-high-value-rid":
            L.append(f"{hv['group']} [{hv['why']}] (0)")     # built-in and empty is the normal state
        else:
            # Granted a dangerous right *and* empty: membership audits see nothing
            # while the right stays live. Whoever can write `member` becomes it.
            L.append(f"{hv['group']} [{hv['why']}] (0 — privilege granted but no members; "
                     f"invisible to membership audits, live to anyone who can write `member`)")
    r = data["reachers"]
    L.append(f"\n== who can reach {data['goal']} targets ({len(r)}) ==")
    if not r:
        L.append("  (no recorded paths from outside the selected goal set)")
    for row in r:
        arrows = " ".join(
            (f"{h['name']} --{h['via']}-->" if h["via"] else h["name"]) for h in row["path"])
        L.append(f"  {row['name']} ({row['hops']} hop{'s' if row['hops'] != 1 else ''}): {arrows}")
    L.extend(_extended_lines(data))
    if data.get("from"):
        L.append(f"\n== Q2 from '{data['from']}' ==")
        if data.get("error"):
            L.append(f"  ! {data['error']}")
            return "\n".join(L)
        p = data["path"]
        L.append(f"Shortest path to {data['goal']} targets ({len(p['goals'])} goals) "
                 f"— endpoint reason: {p['endpoint_reason']}:")
        if p["path"]:
            for hop in p["path"]:
                via = f"  --{hop['via']}-->" if hop["via"] else ""
                L.append(f"  {via} {hop['name']} [{hop['kind']}]")
        else:
            L.append("  (no recorded ACL/membership path; collection and model limits still apply)")
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
    for line in _collector_lines(c):
        L += ["", line]
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
    clues = data["property_clues"]
    L += ["", f"## Recorded property clues (showing {min(5, len(clues))}/{len(clues)})", ""]
    L.extend("- " + property_clue(row) for row in clues[:5])
    if len(clues) > 5:
        L += ["", "Use `bhq clues <collection>` for all selected properties; these are not verified credentials."]
    L += ["", "## Q1 — offline-crackable", "", f"**Kerberoastable ({len(data['kerberoastable'])})**", "",
          "| account | SPN | admincount |", "|---|---|---|"]
    for k in data["kerberoastable"]:
        L.append(f"| `{k['name']}` | `{','.join(k['spns'])}` | {'yes' if k['admincount'] else ''} |")
    L += ["", f"**AS-REP roastable:** {', '.join('`%s`' % a for a in data['asreproastable']) or '(none)'}"]
    L += ["", "## Q4 — special rights", "",
          f"- **Unconstrained delegation:** {', '.join('`%s`' % x for x in data['delegation']['unconstrained']) or '(none)'}"]
    for cd in data["delegation"]["constrained"]:
        L.append(f"- **Constrained delegation:** `{cd['name']}` → {delegation_targets(cd)}")
    L += ["", "**Recorded RBCD configuration (not an executable path):**", ""]
    L.extend("- " + rbcd_finding(row) for row in data["delegation"]["rbcd"])
    if not data["delegation"]["rbcd"]:
        L.append("- (no populated AllowedToAct in loaded computers)")
    L += ["", "**Recorded trusts (direction relative to source; null means not recorded):**", ""]
    L.extend("- " + trust_finding(row) for row in data["trusts"])
    if not data["trusts"]:
        L.append("- (no trust entries in loaded domains; collection scope still applies)")
    L += ["", "**Recorded DCSync rights:**", ""]
    L.extend("- " + dcsync_finding(row) for row in data["dcsync_findings"])
    if not data["dcsync_findings"]:
        L.append("- (no matching recorded grant combination)")
    L += ["", "## High-value groups (derived, not a name list)", "",
          "| group | why | members |", "|---|---|---|"]
    for hv in data["high_value_groups"]:
        members = ", ".join("`%s`" % m for m in hv["members"])
        if not members:
            members = ("_(none)_" if hv["why"] == "well-known-high-value-rid"
                       else "_(none — privilege live but invisible to membership audits)_")
        L.append(f"| `{hv['group']}` | {hv['why']} | {members} |")
    L += ["", f"## Who can reach {data['goal']} targets ({len(data['reachers'])})", ""]
    if not data["reachers"]:
        L.append("_(no recorded paths from outside the selected goal set)_")
    for row in data["reachers"]:
        arrows = " ".join(
            (f"`{h['name']}` —{h['via']}→" if h["via"] else f"`{h['name']}`") for h in row["path"])
        hops = f"{row['hops']} hop" + ("s" if row["hops"] != 1 else "")
        L.append(f"- **{row['name']}** ({hops}): {arrows}")
    L.extend(_extended_lines(data))
    if data.get("from"):
        L += ["", f"## Q2 — from `{data['from']}`"]
        if data.get("error"):
            L.append(f"> {data['error']}")
            return "\n".join(L)
        p = data["path"]
        L += ["", f"**Shortest path to {data['goal']} targets** ({len(p['goals'])} goals; "
              f"the last hop names which one):", ""]
        if p["path"]:
            parts = [
                (f"—{h['via']}→ `{h['name']}`" if h["via"] else f"`{h['name']}`")
                for h in p["path"]
            ]
            L.append("> " + " ".join(parts))
        else:
            L.append("> (no recorded ACL/membership path; collection and model limits still apply)")
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


def render(g: Graph, start_name: str | None = None, fmt: str = "text", goal: str = "high-value") -> str:
    return RENDERERS[fmt](build(g, start_name, goal))
