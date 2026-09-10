"""Load a BloodHound collection (dir of *_users.json… or a .zip) into a Graph.

The Graph normalises SharpHound / bloodhound-python / bloodhound-ce-python JSON
(legacy v4 and CE v6 layouts) into:
  - a SID -> display-name / kind index
  - control edges  (principal --RightName--> target)   from object ACEs
    plus the reverse index (target -> [(principal, right)]), needed to ask
    "who can write to this object?" — the inbound direction
  - member edges   (member --MemberOf--> group), plus the reverse (group -> members)
  - admin edges    (principal --AdminTo/CanRDP/…--> computer), with a `collected` flag
  - domain ACEs    (domain, principal, right)  (for DCSync detection)

Everything downstream (queries, report) works off these.
"""

from __future__ import annotations

import glob
import json
import os
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

# ACEs that give an attacker usable control over the *target* object.
CONTROL_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "WriteAccountRestrictions", "WriteSPN",
    "ReadLAPSPassword", "ReadGMSAPassword", "AddAllowedToAct",
    "WriteAllowedToAct",
}
# Replication rights on the domain object -> DCSync.
DCSYNC_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync"}
# Well-known RIDs of admin-equivalent principals. These are fixed by Microsoft and
# identical in every forest, unlike the *display names*, which are localised — a
# non-English install renames the groups but keeps the RID. Match on these, never
# on names. (S-1-5-32-<RID> for BUILTIN aliases, <domainSID>-<RID> for domain groups.)
WELL_KNOWN_ADMIN_RIDS = {
    500,  # Administrator
    512,  # Domain Admins
    518,  # Schema Admins
    519,  # Enterprise Admins
    520,  # Group Policy Creator Owners
    526,  # Key Admins
    527,  # Enterprise Key Admins
    544,  # BUILTIN\Administrators
    548,  # BUILTIN\Account Operators
    549,  # BUILTIN\Server Operators
    550,  # BUILTIN\Print Operators
    551,  # BUILTIN\Backup Operators
}


def rid_of(sid: str) -> int | None:
    """Trailing RID of a SID, or None. Works for both `<domainSID>-1622` and the
    `DOMAIN.LOCAL-S-1-5-32-544` shape BloodHound uses for BUILTIN aliases."""
    tail = sid.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else None
# Computer local-access collections -> per-computer admin/remote edges.
# Legacy (BloodHound 4.x, meta.version 4-5) puts each local group in its own computer field.
LOCAL_COLLECTIONS = {
    "LocalAdmins": "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "PSRemoteUsers": "CanPSRemote",
    "DcomUsers": "ExecuteDCOM",
}
# BloodHound CE (JSON v6) replaced those four fields with a single `LocalGroups`
# list; each entry names its group by well-known RID in `ObjectIdentifier`
# (`<computerSID>-<RID>`), so the RID — not the localised group name — is the key.
# Only collected groups are emitted, and bloodhound-ce-python skips this collection
# on domain controllers entirely, so an empty list is "not collected", not "empty group".
LOCAL_GROUP_RIDS = {
    544: "AdminTo",       # BUILTIN\Administrators
    555: "CanRDP",        # Remote Desktop Users
    562: "ExecuteDCOM",   # Distributed COM Users
    580: "CanPSRemote",   # Remote Management Users
}
OBJECT_TYPES = ["users", "groups", "computers", "domains", "gpos", "ous", "containers"]
# Only these can hold an ACE, sit in a group, or be a path endpoint, so only these
# answer to a name. AD routinely puts an OU and a group of the same name side by side
# ("IT Admins" the OU, "IT Admins" the group) — treating that as an ambiguous lookup
# would refuse to resolve the very groups a path question is about.
PRINCIPAL_KINDS = {"user", "group", "computer", "domain"}


class CollectionError(ValueError):
    """The input is not a usable, unambiguous BloodHound collection."""


def _data(blob, source: str):
    if isinstance(blob, dict):
        data = blob.get("data")
        if data is None:
            raise CollectionError(f"{source}: JSON object has no 'data' array")
        if not isinstance(data, list):
            raise CollectionError(f"{source}: 'data' must be an array")
        return data
    if isinstance(blob, list):
        return blob
    raise CollectionError(f"{source}: expected a JSON object or array")


def _results(node):
    """A local-collection field is either {'Collected':bool,'Results':[…],'FailureReason':str|None}
    or a bare list. Returns (members, collected, failure_reason) — the reason is what
    separates "the query was refused" from "the group really is empty"; collectors that
    leave it null force both to be read as unknown."""
    if isinstance(node, dict):
        reason = node.get("FailureReason")
        return (node.get("Results") or [], bool(node.get("Collected")),
                reason if isinstance(reason, str) and reason.strip() else None)
    if isinstance(node, list):
        return node, True, None
    return [], False, None


class Graph:
    def __init__(self):
        self.objects: list[dict] = []
        self.by_sid: dict[str, dict] = {}
        self._name: dict[str, str] = {}
        self._kind: dict[str, str] = {}
        self._aliases: dict[str, set[str]] = {}
        self.users: list[dict] = []
        self.groups: list[dict] = []
        self.computers: list[dict] = []
        self.domains: list[dict] = []
        self.control_edges: dict[str, list[tuple[str, str]]] = {}
        self.control_edges_rev: dict[str, list[tuple[str, str]]] = {}
        self.member_edges: dict[str, list[str]] = {}
        self.member_edges_rev: dict[str, list[str]] = {}
        self.admin_edges: dict[str, list[tuple[str, str]]] = {}
        self.local_collection_status: dict[str, dict[str, bool]] = {
            label: {} for label in LOCAL_COLLECTIONS.values()
        }
        # label -> {computer_sid: FailureReason}. Only populated by collectors that
        # actually fill the field; without it an attempted-but-silent group is
        # indistinguishable from a refused query.
        self.local_failures: dict[str, dict[str, str]] = {
            label: {} for label in LOCAL_COLLECTIONS.values()
        }
        self.domain_aces: list[tuple[str, str, str]] = []  # (domain_sid, principal_sid, right)
        self.domain_sids: set[str] = set()            # SIDs of the domain objects themselves
        self.collection_files: dict[str, list[str]] = {t: [] for t in OBJECT_TYPES}

    # ---- lookups -------------------------------------------------------
    def name(self, sid: str) -> str:
        return self._name.get(sid, sid)

    def kind(self, sid: str) -> str:
        return self._kind.get(sid, "?")

    def sid_of(self, query: str) -> str | None:
        """Resolve a name to a SID. Matches full name, samaccountname, or the
        pre-@ short form, case-insensitively. Ambiguous short names deliberately
        return None instead of silently selecting one domain. A raw SID passes
        straight through."""
        matches = self.sid_candidates(query)
        return next(iter(matches)) if len(matches) == 1 else None

    def sid_candidates(self, query: str) -> set[str]:
        """All principals matching a raw SID, qualified name, or short name."""
        if query in self.by_sid:
            return {query}
        return set(self._aliases.get(query.lower(), set()))

    def qualified_name(self, sid: str) -> str:
        """Most domain-specific display name available for ambiguity messages."""
        props = (self.by_sid.get(sid) or {}).get("Properties") or {}
        return props.get("name") or self.name(sid)

    # ---- construction --------------------------------------------------
    def _register(self, obj: dict, kind: str) -> None:
        sid = obj.get("ObjectIdentifier")
        if not sid:
            return
        props = obj.get("Properties") or {}
        self.by_sid[sid] = obj
        self._name[sid] = props.get("samaccountname") or props.get("name") or sid
        self._kind[sid] = kind
        self.objects.append(obj)
        aliases = {sid, props.get("samaccountname"), props.get("name")} if kind in PRINCIPAL_KINDS else set()
        for alias in filter(None, aliases):
            key = str(alias).lower()
            self._aliases.setdefault(key, set()).add(sid)
            if "@" in key:
                self._aliases.setdefault(key.split("@", 1)[0], set()).add(sid)

    def _add_edges(self, obj: dict, is_domain: bool) -> None:
        sid = obj.get("ObjectIdentifier")
        for ace in obj.get("Aces") or []:
            principal = ace.get("PrincipalSID")
            right = ace.get("RightName")
            if not principal or not right:
                continue
            if right in CONTROL_RIGHTS:
                self.control_edges.setdefault(principal, []).append((sid, right))
                self.control_edges_rev.setdefault(sid, []).append((principal, right))
            if is_domain and right in DCSYNC_RIGHTS:
                self.domain_aces.append((sid, principal, right))
        if is_domain:
            self.domain_sids.add(sid)
        # group membership
        if self._kind.get(sid) == "group":
            for m in obj.get("Members") or []:
                msid = m.get("ObjectIdentifier")
                if msid:
                    self.member_edges.setdefault(msid, []).append(sid)
                    self.member_edges_rev.setdefault(sid, []).append(msid)
        # computer local access — one layout per object (a CE computer carries
        # `LocalGroups`, a legacy one the four fields), so either collector line
        # yields the same edges and neither can double-count
        if self._kind.get(sid) == "computer":
            status = {label: False for label in LOCAL_COLLECTIONS.values()}
            if "LocalGroups" in obj:                                # CE v6
                for group in obj.get("LocalGroups") or []:
                    if not isinstance(group, dict):
                        continue
                    label = LOCAL_GROUP_RIDS.get(rid_of(str(group.get("ObjectIdentifier") or "")))
                    if label is None:
                        continue
                    members, collected, reason = _results(group)
                    status[label] = status[label] or collected
                    if reason:
                        self.local_failures[label][sid] = reason
                    self._add_local_members(sid, label, members)
            else:                                                   # legacy v4
                for field, label in LOCAL_COLLECTIONS.items():
                    members, collected, reason = _results(obj.get(field))
                    status[label] = status[label] or collected
                    if reason:
                        self.local_failures[label][sid] = reason
                    self._add_local_members(sid, label, members)
            for label, collected in status.items():
                self.local_collection_status[label][sid] = collected

    def _add_local_members(self, computer_sid: str, label: str, members) -> None:
        for r in members:
            psid = r.get("ObjectIdentifier") if isinstance(r, dict) else None
            if psid:
                self.admin_edges.setdefault(psid, []).append((computer_sid, label))


def _iter_files(path: str):
    """Yield (type, parsed_json) for each recognised BloodHound file under `path`
    (a directory) — used after any zip has been extracted."""
    for t in OBJECT_TYPES:
        # `*_{t}_NN.json` is the continuation file both collectors start after
        # 40000 objects of one type — skipping it would silently drop the overflow.
        patterns = (f"**/*_{t}.json", f"**/{t}.json", f"**/*_{t}_[0-9][0-9].json")
        files = sorted({f for pattern in patterns for f in glob.glob(os.path.join(path, pattern), recursive=True)})
        for f in files:
            try:
                with open(f, encoding="utf-8-sig") as fh:
                    yield t, f, json.load(fh)
            except json.JSONDecodeError as exc:
                raise CollectionError(f"{f}: invalid JSON at line {exc.lineno}, column {exc.colno}") from exc


def _extract_zip(path: str, destination: str) -> None:
    """Extract without permitting an archive member to escape the temp root."""
    root = Path(destination).resolve()
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                target = (root / member.filename).resolve()
                if target != root and root not in target.parents:
                    raise CollectionError(f"{path}: unsafe ZIP member {member.filename!r}")
            archive.extractall(root)
    except zipfile.BadZipFile as exc:
        raise CollectionError(f"{path}: invalid ZIP archive") from exc


def load(path: str) -> Graph:
    """Load from a directory of BloodHound JSON, or a .zip of the same."""
    path = os.fspath(path)
    if not os.path.exists(path):
        raise CollectionError(f"collection path does not exist: {path}")
    if path.lower().endswith(".zip") or (os.path.isfile(path) and zipfile.is_zipfile(path)):
        with TemporaryDirectory() as tmp:
            _extract_zip(path, tmp)
            return _load_dir(tmp)
    if not os.path.isdir(path):
        raise CollectionError(f"collection must be a directory or ZIP: {path}")
    return _load_dir(path)


def _load_dir(path: str) -> Graph:
    g = Graph()
    buckets: dict[str, list[dict]] = {t: [] for t in OBJECT_TYPES}
    seen: dict[str, tuple[str, str]] = {}
    found = False
    for t, source, blob in _iter_files(path):
        found = True
        g.collection_files[t].append(os.path.relpath(source, path))
        for obj in _data(blob, source):
            if not isinstance(obj, dict):
                raise CollectionError(f"{source}: collection entries must be JSON objects")
            sid = obj.get("ObjectIdentifier")
            if not isinstance(sid, str) or not sid:
                raise CollectionError(f"{source}: collection entry has no valid ObjectIdentifier")
            if sid and sid in seen:
                old_type, old_source = seen[sid]
                raise CollectionError(
                    f"duplicate ObjectIdentifier {sid} in {old_source} ({old_type}) and "
                    f"{source} ({t}); do not mix collection snapshots"
                )
            if sid:
                seen[sid] = (t, source)
            buckets[t].append(obj)
    if not found:
        raise CollectionError(f"no recognised BloodHound JSON files under: {path}")
    if not any(buckets.values()):
        raise CollectionError(f"recognised BloodHound files contain no objects: {path}")
    g.users, g.groups = buckets["users"], buckets["groups"]
    g.computers, g.domains = buckets["computers"], buckets["domains"]
    # register all objects first so kind/name is known before edge building
    for t in OBJECT_TYPES:
        kind = t[:-1] if t.endswith("s") else t          # users->user, gpos->gpo, ous->ou
        kind = {"gpo": "gpo", "ou": "ou", "container": "container"}.get(kind, kind)
        for obj in buckets[t]:
            g._register(obj, kind)
    for obj in buckets["users"] + buckets["groups"] + buckets["computers"]:
        g._add_edges(obj, is_domain=False)
    for obj in buckets["domains"]:
        g._add_edges(obj, is_domain=True)
    return g
