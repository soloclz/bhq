"""`bhq` — offline BloodHound analysis CLI.

    bhq report <path> [--from alice]     combined queries and collection limits
    bhq path   <path> <from>               shortest recorded path -> selected targets
    bhq controls <path> <principal> [-d N] what a principal controls (N hops)
    bhq kerberoast <path>                  users with SPNs
    bhq asrep <path>                       users not requiring pre-auth
    bhq deleg <path>                       recorded delegation, including RBCD
    bhq dcsync <path>                      recorded replication grants and membership
    bhq reachers <path>                    everyone with a path to high-value targets
    bhq members <path> <group>            resolve a group's members
    bhq local <path> <principal>          computers the principal is admin/remote on

<path> is a directory of *_users.json… or a BloodHound .zip.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import queries, report
from .loader import CollectionError, load


def _load(args):
    # Every subcommand takes the collection path first. A bare word that is not a
    # path is almost always an option written positionally (`bhq report from bob`
    # instead of `bhq report ./bh --from bob`); argparse cannot tell, so say so.
    if not os.path.exists(args.path) and "/" not in args.path and not args.path.endswith(".zip"):
        print(f"[X] '{args.path}' is not a collection path.\n"
              f"    Usage: bhq {args.command} <path> ...   (path comes first; options use --)",
              file=sys.stderr)
        raise SystemExit(2)
    try:
        return load(args.path)
    except (CollectionError, OSError, UnicodeError) as exc:
        print(f"[X] cannot read collection: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _resolve(g, name):
    sid = g.sid_of(name)
    if not sid:
        candidates = g.sid_candidates(name)
        if candidates:
            print(f"[X] ambiguous principal: {name}", file=sys.stderr)
            for candidate in sorted(candidates):
                print(f"    {g.qualified_name(candidate)} [{candidate}]", file=sys.stderr)
            print("    use a qualified name or SID", file=sys.stderr)
        else:
            print(f"[X] not found: {name}", file=sys.stderr)
        raise SystemExit(1)
    return sid


def cmd_report(args):
    out = report.render(_load(args), args.frm, fmt=args.format, goal=args.goal)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out if out.endswith("\n") else out + "\n")
        print(f"[+] wrote {args.format} report -> {args.output}", file=sys.stderr)
    else:
        print(out)


def cmd_path(args):
    g = _load(args)
    sid = _resolve(g, args.frm)
    path, goals = queries.path_to_goal(g, sid, args.goal)
    print(f"goal: {args.goal} ({len(goals)} loaded targets); recorded ACL/membership paths only")
    if not path:
        print(f"(no recorded path from {args.frm}; collection and model limits still apply)")
        return
    print(f"endpoint reason: {queries.goal_sids(g, args.goal)[path[-1][0]]}")
    for psid, label in path:
        via = f"--{label}--> " if label else ""
        print(f"{via}{g.name(psid)} [{g.kind(psid)}]")


def cmd_controls(args):
    g = _load(args)
    sid = _resolve(g, args.principal)
    rows = queries.controls(g, sid, max_depth=args.depth)
    if not rows:
        print("(no outbound object control)")
    for depth, frm, label, to in rows:
        print(f"{'  ' * depth}{frm} --{label}--> {to}")


def cmd_kerberoast(args):
    for k in queries.kerberoastable(_load(args)):
        tag = "  [admincount]" if k["admincount"] else ""
        print(f"{k['name']}  {','.join(k['spns'])}{tag}")


def cmd_asrep(args):
    for a in queries.asreproastable(_load(args)):
        print(a["name"])


def cmd_deleg(args):
    d = queries.delegation(_load(args))
    print("unconstrained: " + (", ".join(d["unconstrained"]) or "(none)"))
    for c in d["constrained"]:
        print(f"constrained: {c['name']} -> {report.delegation_targets(c)}")
    print("Recorded RBCD configuration; accepted principals do not establish an executable path:")
    for row in d["rbcd"]:
        print(report.rbcd_finding(row))
    if not d["rbcd"]:
        print("(no populated AllowedToAct in loaded computers)")


def cmd_dcsync(args):
    print("Recorded grants through group membership; deny ACEs and token restrictions are not evaluated.")
    rows = queries.dcsync_findings(_load(args))
    for row in rows:
        print(report.dcsync_finding(row))
    if not rows:
        print("(no matching recorded grant combination)")


def cmd_reachers(args):
    g = _load(args)
    print(f"goal: {args.goal}; recorded ACL/membership paths only")
    rows = sorted(queries.who_can_reach_high_value(g, args.goal).items(), key=lambda kv: (kv[1][0], g.name(kv[0])))
    if not rows:
        print("(no recorded paths from outside the selected goal set)")
        return
    for sid, (hops, chain) in rows:
        arrows = " ".join(f"{name} --{via}-->" if via else name for name, via in chain)
        print(f"{g.name(sid)} ({hops}): {arrows}")


def cmd_members(args):
    g = _load(args)
    candidates = {sid for sid in g.sid_candidates(args.group) if g.kind(sid) == "group"}
    if len(candidates) > 1:
        print(f"[X] ambiguous group: {args.group}", file=sys.stderr)
        for sid in sorted(candidates):
            print(f"    {g.qualified_name(sid)} [{sid}]", file=sys.stderr)
        print("    use a qualified name or SID", file=sys.stderr)
        raise SystemExit(1)
    if candidates:
        sid = next(iter(candidates))
        for member in (g.by_sid[sid].get("Members") or []):
            print(g.name(member.get("ObjectIdentifier")))
        return
    print(f"[X] group not found: {args.group}", file=sys.stderr)
    raise SystemExit(1)


def cmd_local(args):
    g = _load(args)
    sid = _resolve(g, args.principal)
    rows = queries.local_admin_of(g, sid)
    if not rows:
        print("(none collected — computer local-group data may be missing)")
    for name, label in rows:
        print(f"{name} ({label})")


def cmd_trusts(args):
    rows = queries.trusts(_load(args))
    print("Recorded trust fields; direction is relative to source, null means not recorded. Access is not verified.")
    for row in rows:
        print(report.trust_finding(row))
    if not rows:
        print("(no trust entries in loaded domains; collection scope still applies)")


OBJECT_KINDS = ["user", "group", "computer", "domain", "gpo", "ou", "container"]


def cmd_objects(args):
    rows = queries.object_index(_load(args), args.kind, args.match)
    for row in rows:
        print(f"{row['kind']} {row['name']} [{row['id']}]")
    if not rows:
        print("(no matching loaded objects)")


def cmd_object(args):
    g = _load(args)
    candidates = queries.object_candidates(g, args.name)
    if len(candidates) != 1:
        label = "ambiguous object" if candidates else "object not found"
        print(f"[X] {label}: {args.name}; use an ObjectIdentifier", file=sys.stderr)
        for sid in candidates:
            print(f"    {g.kind(sid)} {g.qualified_name(sid)} [{sid}]", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(queries.object_details(g, candidates[0]), indent=2, ensure_ascii=False))


def cmd_clues(args):
    rows = queries.property_clues(_load(args), args.kind)
    print("Recorded properties, not verified credentials; use object for the full record.")
    for row in rows:
        print(report.property_clue(row))
    if not rows:
        print("(no selected nonempty properties or flags in loaded objects)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bhq", description="Offline BloodHound JSON analyzer.")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.add_argument("path", help="dir of *_users.json… or a BloodHound .zip")
        s.set_defaults(func=fn)
        return s

    s = add("report", cmd_report, "combined AD analysis and collection limits")
    s.add_argument("--from", dest="frm", help="starting principal for path and control queries")
    s.add_argument("--goal", choices=["high-value", "da"], default="high-value")
    s.add_argument("--format", choices=["text", "md", "json"], default="text", help="output format (default text)")
    s.add_argument("-o", "--output", help="write to this file (for evidence) instead of stdout")

    s = add("path", cmd_path, "shortest recorded path to selected targets")
    s.add_argument("frm", metavar="FROM", help="starting principal")
    s.add_argument("--goal", choices=["high-value", "da"], default="high-value")

    s = add("controls", cmd_controls, "what a principal controls")
    s.add_argument("principal")
    s.add_argument("-d", "--depth", type=int, default=2, help="hops to expand (default 2)")

    add("kerberoast", cmd_kerberoast, "users with SPNs")
    add("asrep", cmd_asrep, "users not requiring Kerberos pre-auth")
    add("deleg", cmd_deleg, "recorded unconstrained, constrained, and RBCD configuration")
    add("dcsync", cmd_dcsync, "replication grants combined per principal and domain")
    s = add("reachers", cmd_reachers, "principals with recorded paths to selected targets")
    s.add_argument("--goal", choices=["high-value", "da"], default="high-value")

    s = add("members", cmd_members, "resolve a group's members")
    s.add_argument("group")

    s = add("local", cmd_local, "computers a principal is admin/remote on")
    s.add_argument("principal")

    add("trusts", cmd_trusts, "recorded trust fields relative to each source domain")
    s = add("objects", cmd_objects, "list loaded objects, including GPOs and OUs")
    s.add_argument("--kind", choices=OBJECT_KINDS)
    s.add_argument("--match", default="", help="case-insensitive name or identifier substring")
    s = add("object", cmd_object, "show one complete recorded object as JSON")
    s.add_argument("name", help="exact name or ObjectIdentifier")
    s = add("clues", cmd_clues, "show selected recorded properties and flags")
    s.add_argument("--kind", choices=OBJECT_KINDS)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    # Every subcommand takes the collection path as its first positional, so a
    # stray extra word is nearly always an option written positionally
    # (`bhq report from bob`). argparse would just say "unrecognized arguments",
    # which sends people looking in the wrong place.
    args, extra = parser.parse_known_args(argv)
    if extra:
        print(f"[X] unexpected argument(s): {' '.join(extra)}\n"
              f"    bhq {args.command} takes the collection path first; "
              f"options are passed with -- (e.g. `bhq report ./bh --from bob`).",
              file=sys.stderr)
        return 2
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
