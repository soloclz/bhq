"""Enumerate every observed field path, including new and raw-only fields."""
from collections import defaultdict
from .common import evidence

# A field having an outlet does not mean every nested value is modeled.
OUTLETS = {
    'Sessions': 'sessions', 'PrivilegedSessions': 'sessions', 'RegistrySessions': 'sessions',
    'LocalGroups': 'local access', 'LocalAdmins': 'local access', 'RemoteDesktopUsers': 'local access',
    'DcomUsers': 'local access', 'PSRemoteUsers': 'local access',
    'HasSIDHistory': 'sid-history', 'UserRights': 'user-rights',
    'Links': 'policy', 'ChildObjects': 'policy', 'ContainedBy': 'policy', 'GPOChanges': 'policy',
    'AllowedToAct': 'delegation / conditional route', 'AllowedToDelegate': 'delegation / conditional route',
    'Aces': 'ACL queries (selected RightName values)', 'Members': 'membership', 'PrimaryGroupSID': 'membership',
    'Trusts': 'trusts', 'EnabledCertTemplates': 'adcs', 'CARegistryData': 'adcs',
    'HttpEnrollmentEndpoints': 'adcs', 'HostingComputer': 'adcs', 'GroupLink': 'adcs',
    'ObjectIdentifier': 'object index', 'IsDeleted': 'conditional route exclusion',
}
PROPERTY_OUTLETS = {
    'sidhistory': 'sid-history', 'blocksinheritance': 'policy',
    'name': 'object index', 'samaccountname': 'object index',
    'description': 'clues', 'info': 'clues', 'homedirectory': 'clues', 'logonscript': 'clues',
    'profilepath': 'clues', 'userpassword': 'clues', 'unixpassword': 'clues', 'unicodepassword': 'clues', 'sfupassword': 'clues',
    'hasspn': 'kerberoast', 'serviceprincipalnames': 'kerberoast', 'dontreqpreauth': 'asrep',
    'unconstraineddelegation': 'delegation', 'allowedtodelegate': 'delegation',
    'admincount': 'clues', 'enabled': 'clues', 'passwordnotreqd': 'clues', 'trustedtoauth': 'clues', 'haslaps': 'clues',
}


# Known leaf shapes, not only top-level family names: new nested fields remain visible as raw-only.
MEMBER = {'ObjectIdentifier', 'ObjectType'}
STATUS = {'Collected', 'FailureReason'}
ACE = {'PrincipalSID', 'PrincipalType', 'RightName', 'IsInherited', 'InheritanceHash'}
SUFFIXES = {
    'Aces': ACE, 'Members': MEMBER, 'AllowedToAct': MEMBER, 'AllowedToDelegate': MEMBER,
    'HasSIDHistory': {''} | MEMBER, 'ChildObjects': MEMBER, 'ContainedBy': MEMBER,
    'Links': {'GUID', 'IsEnforced'}, 'GroupLink': MEMBER, 'EnabledCertTemplates': MEMBER,
    'Trusts': {'TargetDomainSid', 'TargetDomainName', 'TrustDirection', 'TrustType', 'IsTransitive', 'SidFilteringEnabled', 'TrustAttributes'},
    'UserRights': STATUS | {'Privilege', 'LocalNames'} | {'Results.' + k for k in MEMBER},
    'LocalGroups': STATUS | {'ObjectIdentifier', 'Name', 'LocalNames'} | {'Results.' + k for k in MEMBER},
    'GPOChanges': {f + '.' + k for f in ('AffectedComputers', 'LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers') for k in MEMBER},
    'CARegistryData': {'CASecurity.' + k for k in STATUS} | {'CASecurity.Data.' + k for k in ACE}
        | {f + '.' + k for f in ('EnrollmentAgentRestrictions', 'IsUserSpecifiesSanEnabled', 'RoleSeparationEnabled') for k in STATUS | {'Value', 'Restrictions'}},
    'HttpEnrollmentEndpoints': STATUS | {'Result.' + k for k in ('Url', 'Type', 'Status', 'ADCSWebEnrollmentHTTP', 'ADCSWebEnrollmentHTTPS', 'ADCSWebEnrollmentEPA')},
}
for _field in ('Sessions', 'PrivilegedSessions', 'RegistrySessions'):
    SUFFIXES[_field] = STATUS | {'Results.UserSID', 'Results.ComputerSID'}
for _field in ('LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers'):
    SUFFIXES[_field] = STATUS | MEMBER | {'Results.' + k for k in MEMBER}


def leaves(value, path=''):
    if isinstance(value, dict) and value:
        for key in sorted(value):
            yield from leaves(value[key], f'{path}.{key}' if path else key)
    elif isinstance(value, list) and value:
        for item in value:
            yield from leaves(item, path + '[]')
    else:
        yield path


def inventory(g):
    from ..loader import ADCS_TYPES
    entries = defaultdict(lambda: {'objects': set(), 'examples': []})
    for obj in g.objects:
        sid, kind = obj['ObjectIdentifier'], g.kind(obj['ObjectIdentifier'])
        for field in sorted(set(leaves(obj))):
            row = entries[(kind, field)]
            row['objects'].add(sid)
            if len(row['examples']) < 3:
                row['examples'].append(evidence(g, sid, field))
    rows = []
    for (kind, field), row in sorted(entries.items()):
        root = field.split('.', 1)[0].removesuffix('[]')
        outlet = OUTLETS.get(root)
        normalized = field.replace('[]', '')
        suffix = normalized.split('.', 1)[1] if '.' in normalized else ''
        if suffix and suffix not in SUFFIXES.get(root, set()):
            outlet = None
        if root == 'Properties':
            prop = field.split('.', 1)[-1].split('[]', 1)[0]
            from .pki import TEMPLATE_FIELDS
            pki_properties = set(TEMPLATE_FIELDS) | {'name', 'domain', 'domainsid', 'distinguishedname', 'description',
                'oid', 'caname', 'dnshostname', 'certthumbprint', 'certthumbprints', 'certchain',
                'unresolvedpublishedtemplates', 'casecuritycollected', 'enrollmentagentrestrictionscollected',
                'isuserspecifiessanenabledcollected', 'roleseparationenabledcollected'}
            outlet = 'adcs properties' if kind in ADCS_TYPES.values() and prop in pki_properties else PROPERTY_OUTLETS.get(prop)
        rows.append({'kind': kind, 'field': field, 'object_count': len(row['objects']),
                     'status': 'query-outlet' if outlet else 'raw-only', 'outlet': outlet or 'object',
                     'examples': row['examples']})
    return {'fields': rows, 'unhandled_files': g.unhandled_files,
            'limitations': ['query-outlet identifies a known field shape with a dedicated outlet, not a verified effective-access conclusion.',
                            'raw-only fields remain available through object; counts describe only loaded input.']}
