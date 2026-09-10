"""Analysis functions over a loaded Graph. Each returns plain data; formatting
lives in `report`/`cli`. Adding a new question = add a function here + wire a
subcommand in `cli`."""

from __future__ import annotations

from collections import deque

from .loader import WELL_KNOWN_ADMIN_RIDS, Graph, rid_of

# "High value" is derived, not listed. Three tiers, in decreasing order of how
# universal they are:
#   1. schema    — WELL_KNOWN_ADMIN_RIDS (loader): fixed by Microsoft, same in
#                  every forest, immune to renaming and localisation.
#   2. derived   — whatever the collected ACEs say is dangerous: replication
#                  rights on the domain object (DCSync), or full control of it.
#                  This is what catches *custom* groups an admin invented, which
#                  no pre-written list can contain.
#   3. judgement — the handful of privileged groups Windows creates without a
#                  well-known SID, so only the name identifies them. Kept small
#                  and overridable, and deliberately NOT dressed up as derived.
# Deliberately NOT here: `Remote Management Users` (S-1-5-32-580) grants WinRM
# access, not administrative rights — treating it as a goal reports compromise
# where there is none. Nor `Domain Controllers` (RID 516), which is a grouping of
# machines rather than an admin group; control *of* a DC computer object is a
# separate question, better answered by a computer-object query than by making
# every DC a path goal.
NAMED_HIGH_VALUE_GROUPS = {"DNSADMINS"}

DOMAIN_CONTROL_RIGHTS = {"GenericAll", "WriteDacl", "WriteOwner", "Owns"}

ANALYSIS_SCOPE = {
    "path_edges": ["ACL object control", "group membership"],
    "separate_findings": [
        "Kerberoast", "AS-REP roast", "delegation", "DCSync",
        "local admin and remote access",
    ],
    "not_modeled": [
        "domain/forest trust traversal",
        "GPO links and OU inheritance",
        "AD CS certificate attack paths",
        "interactive sessions",
        "edge exploitation preconditions",
        "Entra ID and hybrid identity",
    ],
}


def _p(obj):
    return obj.get("Properties") or {}


def kerberoastable(g: Graph) -> list[dict]:
    out = []
    for u in g.users:
        p = _p(u)
        if p.get("hasspn") and (p.get("samaccountname") or "").lower() != "krbtgt":
            out.append({
                "name": p.get("samaccountname"),
                "spns": p.get("serviceprincipalnames") or [],
                "admincount": bool(p.get("admincount")),
                "enabled": p.get("enabled", True),
                "pwdlastset": p.get("pwdlastset"),
            })
    return out


def asreproastable(g: Graph) -> list[dict]:
    return [
        {"name": _p(u).get("samaccountname"), "enabled": _p(u).get("enabled", True)}
        for u in g.users
        if _p(u).get("dontreqpreauth")
    ]


def delegation(g: Graph) -> dict:
    unconstrained, constrained = [], []
    for obj in g.computers + g.users:
        p = _p(obj)
        if p.get("unconstraineddelegation"):
            unconstrained.append(p.get("samaccountname"))
        atd = p.get("allowedtodelegate") or []
        if atd:
            constrained.append({"name": p.get("samaccountname"), "to": atd})
    return {"unconstrained": unconstrained, "constrained": constrained}


def dcsync_principal_sids(g: Graph) -> set[str]:
    """SIDs holding replication rights on the domain object — GetChanges plus
    GetChangesAll (both are required; either alone cannot pull secrets), or the
    combined DCSync edge some collectors post-process them into. The rights must
    belong to the same principal on the same domain object. Group-derived rights
    are not combined here; these findings describe directly recorded ACEs."""
    by_domain_principal: dict[tuple[str, str], set[str]] = {}
    for domain, principal, right in g.domain_aces:
        by_domain_principal.setdefault((domain, principal), set()).add(right)
    return {
        p for (_, p), rights in by_domain_principal.items()
        if "DCSync" in rights or ({"GetChanges", "GetChangesAll"} <= rights)
    }


def dcsync_principals(g: Graph) -> list[str]:
    """Display names of the DCSync-capable principals."""
    return sorted(g.name(s) for s in dcsync_principal_sids(g))


def high_value_sids(g: Graph) -> dict[str, str]:
    """Every principal that is admin-equivalent, mapped to *why*. This replaces
    what used to be a hard-coded list of group names — a list can only hold names
    someone thought of in advance, so it structurally misses the custom groups an
    admin invented, which is exactly where over-permissive rights accumulate."""
    out: dict[str, str] = {}
    for sid in g.by_sid:
        if g.kind(sid) in ("user", "group") and rid_of(sid) in WELL_KNOWN_ADMIN_RIDS:
            out[sid] = "well-known-admin-rid"
    for sid in dcsync_principal_sids(g):
        out.setdefault(sid, "dcsync-on-domain")
    for dom in g.domain_sids:
        for principal, right in g.control_edges_rev.get(dom, []):
            if right in DOMAIN_CONTROL_RIGHTS:
                out.setdefault(principal, "controls-domain-object")
    for grp in g.groups:
        sid = grp.get("ObjectIdentifier")
        name = (_p(grp).get("name") or "").upper().split("@")[0]
        if sid and name in NAMED_HIGH_VALUE_GROUPS:
            out.setdefault(sid, "named-privileged-group")
    return out


def high_value_members(g: Graph) -> list[tuple[str, list[str], str]]:
    """(group name, members, why-it-is-high-value) for every high-value *group*.
    Empty groups are kept, not filtered: a privileged group with no members is
    invisible to membership-based audits while its rights stay live, so it is a
    target rather than a dead end — whoever can write its `member` attribute
    becomes it."""
    out = []
    for sid, reason in high_value_sids(g).items():
        if g.kind(sid) != "group":
            continue
        grp = g.by_sid.get(sid) or {}
        members = sorted(g.name(m.get("ObjectIdentifier")) for m in (grp.get("Members") or []))
        out.append((g.name(sid), members, reason))
    return sorted(out)


def controls(g: Graph, sid: str, max_depth: int = 2) -> list[tuple[int, str, str, str]]:
    """BFS the outbound control+membership graph from `sid`.
    Returns (depth, from_name, edge_label, to_name) tuples."""
    seen = {sid}
    out = []
    frontier = deque([(sid, 0)])
    while frontier:
        cur, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        edges = [(t, r) for (t, r) in g.control_edges.get(cur, [])]
        edges += [(gr, "MemberOf") for gr in g.member_edges.get(cur, [])]
        for nxt, label in edges:
            out.append((depth, g.name(cur), label, g.name(nxt)))
            if nxt not in seen:
                seen.add(nxt)
                frontier.append((nxt, depth + 1))
    return out


def shortest_path(g: Graph, start_sid: str, goal_sids: set[str]) -> list[tuple[str, str]] | None:
    """Shortest control/membership path start -> any goal.
    Returns [(sid, edge_used_to_reach_it), …]; first hop's edge is None."""
    prev: dict[str, tuple[str | None, str | None]] = {start_sid: (None, None)}
    q = deque([start_sid])
    goal = None
    while q:
        cur = q.popleft()
        if cur in goal_sids and cur != start_sid:
            goal = cur
            break
        nexts = [(t, r) for (t, r) in g.control_edges.get(cur, [])]
        nexts += [(gr, "MemberOf") for gr in g.member_edges.get(cur, [])]
        for nxt, label in nexts:
            if nxt not in prev:
                prev[nxt] = (cur, label)
                q.append(nxt)
    if goal is None:
        return None
    chain = []
    x = goal
    while x is not None:
        parent, label = prev[x]
        chain.append((x, label))
        x = parent
    return list(reversed(chain))


def path_to_da(g: Graph, start_sid: str) -> tuple[list[tuple[str, str]] | None, list[str]]:
    """Shortest path from start to any admin-equivalent principal.

    The goal set comes from high_value_sids(), so a custom group that was granted
    DCSync counts as arriving — reaching it *is* domain compromise, even though it
    is not a member of Domain Admins and may have no members at all."""
    goals = high_value_sids(g)
    return shortest_path(g, start_sid, set(goals)), sorted(g.name(s) for s in goals)


def who_can_reach_high_value(g: Graph) -> dict[str, tuple[int, list[tuple[str, str]]]]:
    """One backward BFS from the whole goal set over the reversed graph, giving
    every principal that can reach admin-equivalence plus the path it would take.

    Backwards, because the goals are few and the answer is wanted for everyone:
    one traversal replaces one-BFS-per-foothold, and it also answers the question
    the defender asks — *who in this domain can get to DA* — which forward search
    from a chosen foothold can never produce."""
    goals = high_value_sids(g)
    dist: dict[str, int] = {s: 0 for s in goals}
    prev: dict[str, tuple[str, str]] = {}
    q = deque(goals)
    while q:
        cur = q.popleft()
        inbound = list(g.control_edges_rev.get(cur, []))
        inbound += [(m, "MemberOf") for m in g.member_edges_rev.get(cur, [])]
        for src, right in inbound:
            if src not in dist:
                dist[src] = dist[cur] + 1
                prev[src] = (cur, right)
                q.append(src)
    out = {}
    for sid, d in dist.items():
        if d == 0:
            continue
        chain, x = [], sid
        while x in prev:
            nxt, right = prev[x]
            chain.append((g.name(x), right))
            x = nxt
        chain.append((g.name(x), ""))
        out[sid] = (d, chain)
    return out


def local_admin_of(g: Graph, sid: str) -> list[tuple[str, str]]:
    """Computers where `sid` (directly, or via a group it belongs to) has a local
    edge. Only as good as what was collected (see coverage())."""
    principals = {sid} | set(_transitive_groups(g, sid))
    out = []
    for p in principals:
        for comp_sid, label in g.admin_edges.get(p, []):
            out.append((g.name(comp_sid), label))
    return sorted(set(out))


def _transitive_groups(g: Graph, sid: str) -> set[str]:
    seen, q = set(), deque([sid])
    while q:
        cur = q.popleft()
        for gr in g.member_edges.get(cur, []):
            if gr not in seen:
                seen.add(gr)
                q.append(gr)
    return seen


def coverage(g: Graph) -> dict:
    """How complete is the collection, per local-access capability, in three states:

      total - attempted   the collector never asked (method off, host unresolved
                          or unreachable) — those edges are unknown
      attempted - answered  it asked and got nothing back. If the collector filled
                          `FailureReason` the diagnostics name it; bloodhound.py
                          leaves it empty in both collector lines, and then a refused
                          SAMR query and a genuinely empty group are indistinguishable
                          here — read it as unknown, not zero
      answered            it asked and members came back
    """
    total = len(g.computers)
    answered: dict[str, set[str]] = {label: set() for label in g.local_collection_status}
    for edges in g.admin_edges.values():
        for computer_sid, label in edges:
            answered[label].add(computer_sid)
    local = {
        label: {
            "attempted": sum(1 for value in status.values() if value),
            "answered": len(answered[label]),
            "total": total,
        }
        for label, status in g.local_collection_status.items()
    }
    return {
        "users": len(g.users), "groups": len(g.groups), "computers": total,
        "local_collections": local,
        "files": {kind: len(files) for kind, files in g.collection_files.items() if files},
    }


def diagnostics(g: Graph) -> list[str]:
    """Runtime limitations that must accompany negative findings."""
    warnings = []
    if not g.users:
        warnings.append("users collection is missing or empty; roast and user-path results are incomplete")
    if not g.groups:
        warnings.append("groups collection is missing or empty; membership paths are incomplete")
    if not g.domains:
        warnings.append("domains collection is missing or empty; DCSync detection is unavailable")
    if not g.computers:
        warnings.append("computers collection is missing or empty; local/remote access cannot be assessed")
    else:
        local = coverage(g)["local_collections"]
        incomplete = {label: c for label, c in local.items() if c["attempted"] < c["total"]}
        if incomplete:
            attempts = {(c["attempted"], c["total"]) for c in incomplete.values()}
            counts = ("%d/%d" % attempts.pop() if len(attempts) == 1 else
                      ", ".join(f"{label} {c['attempted']}/{c['total']}" for label, c in incomplete.items()))
            warnings.append(
                f"local-group collection was attempted on {counts} computers; "
                f"the missing {'/'.join(incomplete)} edges are unknown, not absent"
            )
        mute = {label: c for label, c in local.items() if c["attempted"] > c["answered"]}
        if mute:
            shapes = {(c["attempted"] - c["answered"], c["attempted"]) for c in mute.values()}
            where = ("on %d of %d attempted computers" % shapes.pop() if len(shapes) == 1 else
                     "on some attempted computers (" + ", ".join(
                         f"{label} {c['attempted'] - c['answered']}/{c['attempted']}"
                         for label, c in mute.items()) + ")")
            reasons = sorted({r for label in mute for r in g.local_failures[label].values()})
            why = (" the collector reported: " + "; ".join(reasons) + " —" if reasons else
                   " the collector leaves FailureReason empty, so a refused query and an "
                   "empty group look identical —")
            warnings.append(
                f"{', '.join(mute)} came back with no members {where};{why} "
                "confirm access empirically (nxc smb -> Pwn3d!)"
            )
    if len(g.domains) > 1:
        warnings.append(
            f"{len(g.domains)} domains loaded, but trust traversal is not modeled; "
            "use a SID or qualified name for ambiguous principals"
        )
    kinds = {g.kind(sid) for sid in g.by_sid}
    if "gpo" in kinds or "ou" in kinds:
        warnings.append("GPO/OU objects are loaded, but policy links and OU inheritance are not modeled")
    return warnings
