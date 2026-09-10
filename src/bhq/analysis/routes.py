"""Conditional routes over typed capability states, with evidence per transition.

A computer account (principal), a directory object (object) and administrative
access to its host (host) are distinct states. Remote login alone never supplies
host administration. A historical SID supplies grants, not the owner's password.
"""
from collections import defaultdict, deque
from .common import evidence, identifier, ref
from .observations import local_access, sessions, sid_history
from .policy import policy
from ..loader import CONTROL_RIGHTS

CONTROL = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns',
           'ForceChangePassword', 'AddMember', 'AddSelf', 'AllExtendedRights',
           'AddKeyCredentialLink'}


def relationships(g):
    rows = []

    def add(src, source_state, dst, target_state, label, proof, requires=()):
        if not src or not dst:
            return
        # Unresolved objects stay visible in observations, not traversable by name guesses.
        if src not in g.by_sid or dst not in g.by_sid:
            return
        rows.append({'source': ref(g, src), 'source_state': source_state, 'target': ref(g, dst),
                     'target_state': target_state, 'relationship': label, 'evidence': proof,
                     'requires': list(requires)})

    for obj in g.objects:
        owner, kind = obj['ObjectIdentifier'], g.kind(obj['ObjectIdentifier'])
        if obj.get('IsDeleted') is True:
            continue
        for i, ace in enumerate(obj.get('Aces') or []):
            src, right = ace.get('PrincipalSID'), ace.get('RightName')
            if right not in CONTROL_RIGHTS:
                continue
            target_state = 'object'
            if kind == 'user' and right in CONTROL - {'AddMember', 'AddSelf'}:
                target_state = 'principal'
            elif kind == 'group' and right in CONTROL - {'ForceChangePassword', 'AddKeyCredentialLink'}:
                target_state = 'principal'
            elif kind == 'computer' and right in {'GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'ForceChangePassword'}:
                target_state = 'principal'  # Account control is not host administration.
            for source_state in ('principal', 'sid'):
                add(src, source_state, owner, target_state, right, [evidence(g, owner, f'Aces[{i}]')],
                    ['verify the operation allowed on this object type, effective ACL and account prerequisites'])
        if kind == 'group':
            for i, member in enumerate(obj.get('Members') or []):
                add(identifier(member), 'principal', owner, 'principal', 'MemberOf',
                    [evidence(g, owner, f'Members[{i}]')], ['membership is effective in the authentication token'])
        if kind in ('user', 'computer'):
            add(owner, 'principal', obj.get('PrimaryGroupSID'), 'principal', 'MemberOf',
                [evidence(g, owner, 'PrimaryGroupSID')], ['primary group is effective in the authentication token'])
            for i, target in enumerate(obj.get('AllowedToDelegate') or []):
                # Host capability is conditional; the target must be a loaded computer, not an SPN/name guess.
                dst = identifier(target)
                if g.kind(dst) == 'computer':
                    add(owner, 'principal', dst, 'host', 'AllowedToDelegate',
                        [evidence(g, owner, f'AllowedToDelegate[{i}]')],
                        ['control of delegating account credential', 'eligible impersonated identity with administrative access',
                         'usable service/SPN and protocol transition or forwardable ticket', 'reachable service accepting the ticket'])
        if kind == 'computer':
            for i, principal in enumerate(obj.get('AllowedToAct') or []):
                add(identifier(principal), 'principal', owner, 'host', 'AllowedToAct',
                    [evidence(g, owner, f'AllowedToAct[{i}]')],
                    ['controlled service principal accepted by this descriptor', 'eligible impersonated identity with administrative access',
                     'KDC and target service accept the delegation'])
    for row in local_access(g):
        if row['state'] != 'recorded' or not row['right']:
            continue
        for principal in row['principals']:
            for state in ('principal', 'sid'):
                add(principal['id'], state, row['computer']['id'], 'host' if row['right'] == 'AdminTo' else 'remote',
                    row['right'], [row['evidence']], ['current effective local membership, logon policy and service reachability'])
    for row in sessions(g):
        if row['state'] != 'recorded':
            continue
        for entry in row['entries']:
            if entry['consistent']:
                add(entry['computer']['id'], 'host', entry['user']['id'], 'principal', 'HasSession',
                    [entry['evidence']], ['session is still present',
                     f"{row['method']} observation does not establish interactive logon or usable credential material",
                     'available credential or token access despite host protections'])
    for row in sid_history(g):
        add(row['principal']['id'], 'principal', row['historical']['id'], 'sid', 'HasSIDHistory', [row['evidence']],
            ['historical SID is present in the effective token and survives SID filtering; not control of the historical account'])
    pol = policy(g)
    for effect in pol['effects']:
        if effect['inheritance'] != 'candidate':
            continue
        kind = effect['target']['kind']
        if g.kind(effect['gpo']['id']) == 'gpo':
            add(effect['gpo']['id'], 'object', effect['target']['id'], 'host' if kind == 'computer' else 'principal',
                'GPOAppliesCandidate', effect['evidence'], ['ability to modify effective GPO content including SYSVOL'] + effect['requires'])
    for change in pol['changes']:
        for right, principals in change['groups'].items():
            for principal in principals:
                for computer in change['affected_computers']:
                    if computer['kind'] == 'computer':
                        add(principal['id'], 'principal', computer['id'], 'host' if right == 'AdminTo' else 'remote',
                            'GPOChanges:' + right, [change['evidence']],
                            ['collector-projected local membership is applied; verify filtering, precedence and subsequent changes'])
    # Deleted objects cannot be intermediate identities either.
    return [r for r in rows if not any(g.by_sid[r[k]['id']].get('IsDeleted') is True for k in ('source', 'target'))]


def route(g, start, goals, target_state='principal'):
    """Shortest conditional route; explicit typed target avoids SID/object confusion."""
    edges = defaultdict(list)
    for row in relationships(g):
        edges[(row['source']['id'], row['source_state'])].append(row)
    initial = (start, 'principal')
    queue, prev = deque([initial]), {initial: None}
    found = None
    while queue:
        state = queue.popleft()
        if state[0] in goals and state[1] == target_state:
            found = state
            break
        for edge in edges[state]:
            nxt = (edge['target']['id'], edge['target_state'])
            if nxt not in prev:
                prev[nxt] = (state, edge)
                queue.append(nxt)
    steps = None
    if found:
        steps = []
        while prev[found] is not None:
            parent, edge = prev[found]
            steps.append(edge)
            found = parent
        steps.reverse()
    return {'start': ref(g, start), 'target_state': target_state,
            'goals': [ref(g, s) for s in sorted(goals)], 'steps': steps,
            'status': 'candidate' if steps is not None else 'no-modeled-route',
            'limitations': ['Conditional investigation route, not a verified execution path.',
                            'No automatic AD CS or trust-boundary transitions; those require separate conditions.']}
