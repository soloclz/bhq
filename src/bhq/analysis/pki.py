"""AD CS object analysis with explicit grant provenance and unknown conditions."""
from .common import evidence, identifier, membership, ref
from ..loader import ADCS_TYPES, CONTROL_RIGHTS

TEMPLATE_FIELDS = ('authenticationenabled', 'enrolleesuppliessubject', 'requiresmanagerapproval',
                   'authorizedsignatures', 'effectiveekus', 'ekus', 'certificateapplicationpolicy',
                   'schemaversion', 'nosecurityextension', 'issuancepolicies', 'applicationpolicies')
PKI_RIGHTS = CONTROL_RIGHTS | {'Enroll', 'AutoEnroll', 'ManageCA', 'ManageCertificates',
                              'WritePKINameFlag', 'WritePKIEnrollmentFlag', 'WriteOwnerRaw', 'OwnsRaw'}


def grants(g, obj, principal=None):
    owner = obj['ObjectIdentifier']
    paths = membership(g, principal) if principal else None
    entries = [(ace, f'Aces[{i}]', True) for i, ace in enumerate(obj.get('Aces') or [])]
    security = (obj.get('CARegistryData') or {}).get('CASecurity') or {}
    for i, ace in enumerate(security.get('Data') or []):
        entries.append((ace, f'CARegistryData.CASecurity.Data[{i}]',
                        security.get('Collected') is True and not security.get('FailureReason')))
    rows = []
    for ace, field, confirmed in entries:
        if not isinstance(ace, dict):
            continue
        sid, right = ace.get('PrincipalSID'), ace.get('RightName')
        if right not in PKI_RIGHTS or (paths is not None and sid not in paths):
            continue
        rows.append({'principal': ref(g, sid), 'right': right, 'collection_confirmed': confirmed,
                     'membership_path': paths.get(sid) if paths else None, 'raw': ace,
                     'evidence': evidence(g, owner, field)})
    return rows


def _bool(value):
    return value if type(value) is bool else None


def _enroll(rows, template=False):
    # AutoEnroll alone and GenericAll on a CA directory object are not CA service grants.
    return any(row['collection_confirmed'] and (
        row['right'] in ('Enroll', 'AllExtendedRights', 'GenericAll') if template else
        row['right'] == 'Enroll' and row['evidence']['field'].startswith('CARegistryData.CASecurity.')) for row in rows)


def adcs(g, principal=None):
    cas = [o for o in g.objects if g.kind(o['ObjectIdentifier']) == 'enterpriseca']
    stores = [o for o in g.objects if g.kind(o['ObjectIdentifier']) == 'ntauthstore']
    objects, templates, publications, policies = [], [], [], []
    for obj in g.objects:
        sid, props = obj['ObjectIdentifier'], obj.get('Properties') or {}
        kind = g.kind(sid)
        if kind not in ADCS_TYPES.values():
            continue
        objects.append({'object': ref(g, sid), 'properties': props, 'grants': grants(g, obj, principal),
                        'evidence': evidence(g, sid, '$')})
        if kind == 'issuancepolicy':
            policies.append({'policy': ref(g, sid), 'oid': props.get('oid'),
                             'group': ref(g, identifier(obj.get('GroupLink'))),
                             'evidence': evidence(g, sid, 'GroupLink')})
    certificate_nodes = [o for o in g.objects if g.kind(o['ObjectIdentifier']) in ('rootca', 'aiaca', 'enterpriseca')]
    ca_rows = []
    for ca in cas:
        sid, props = ca['ObjectIdentifier'], ca.get('Properties') or {}
        thumb = props.get('certthumbprint')
        trust_matches = [ref(g, store['ObjectIdentifier']) for store in stores
                         if isinstance(thumb, str) and thumb and any(
                             isinstance(v, str) and v.casefold() == thumb.casefold()
                             for v in (store.get('Properties') or {}).get('certthumbprints') or [])]
        ca_rows.append({'ca': ref(g, sid), 'hosting_computer': ref(g, identifier(ca.get('HostingComputer'))),
                        'ntauth_thumbprint_matches': trust_matches,
                        'chain_matches': [{'thumbprint': thumbprint, 'objects': [ref(g, o['ObjectIdentifier']) for o in certificate_nodes
                            if isinstance(thumbprint, str) and thumbprint and str((o.get('Properties') or {}).get('certthumbprint', '')).casefold() == thumbprint.casefold()]}
                            for thumbprint in props.get('certchain') or []],
                        'registry': ca.get('CARegistryData'), 'http_endpoints': ca.get('HttpEnrollmentEndpoints'),
                        'grants': grants(g, ca, principal), 'evidence': evidence(g, sid, '$')})
        for i, template in enumerate(ca.get('EnabledCertTemplates') or []):
            tid = identifier(template)
            publications.append({'ca': ref(g, sid), 'template': ref(g, tid),
                                 'resolved': g.kind(tid) == 'certtemplate',
                                 'evidence': evidence(g, sid, f'EnabledCertTemplates[{i}]')})
        for i, name in enumerate(props.get('unresolvedpublishedtemplates') or []):
            publications.append({'ca': ref(g, sid), 'template': ref(g, name), 'resolved': False,
                                 'evidence': evidence(g, sid, f'Properties.unresolvedpublishedtemplates[{i}]')})
    for obj in g.objects:
        sid, props = obj['ObjectIdentifier'], obj.get('Properties') or {}
        if g.kind(sid) != 'certtemplate':
            continue
        rights = grants(g, obj, principal)
        auth, subject = _bool(props.get('authenticationenabled')), _bool(props.get('enrolleesuppliessubject'))
        approval, signatures = _bool(props.get('requiresmanagerapproval')), props.get('authorizedsignatures')
        checks = {'authentication_enabled': auth, 'enrollee_supplies_subject': subject,
                  'no_manager_approval': None if approval is None else not approval,
                  'no_authorized_signatures': signatures == 0 if type(signatures) is int and signatures >= 0 else None}
        state = 'not-matched' if False in checks.values() else 'unknown' if None in checks.values() else 'matched'
        published = [p for p in publications if p['resolved'] and p['template']['id'] == sid]
        enrollment = []
        for publication in published:
            ca_id = publication['ca']['id']
            ca_rights = grants(g, g.by_sid[ca_id], principal)
            # Without a selected subject, grants held by different principals cannot be combined.
            enrollment.append({'ca': publication['ca'],
                               'template_grant_found': _enroll(rights, template=True) if principal else None,
                               'ca_grant_found': _enroll(ca_rights) if principal else None,
                               'ca_grants': ca_rights, 'publication_evidence': publication['evidence']})
        clues = []
        ekus = props.get('effectiveekus')
        if isinstance(ekus, list):
            if not ekus or '2.5.29.37.0' in ekus:
                clues.append('ESC2 template-usage candidate: no effective EKU restriction or Any Purpose')
            if '1.3.6.1.4.1.311.20.2.1' in ekus:
                clues.append('ESC3 enrollment-agent usage; target template and agent restrictions require review')
        if props.get('nosecurityextension') is True:
            clues.append('ESC9 setting: security extension disabled; mapping and authentication conditions require review')
        if any(r['right'] in {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'WritePKINameFlag', 'WritePKIEnrollmentFlag'} for r in rights):
            clues.append('ESC4 object-control candidate; specific writable attributes and issuance conditions require review')
        templates.append({'template': ref(g, sid), 'settings': {k: props[k] for k in TEMPLATE_FIELDS if k in props},
                          'esc1_template_checks': checks, 'esc1_template_state': state,
                          'publication_count': len(published), 'grants': rights, 'enrollment': enrollment,
                          'clues': clues,
                          'issuance_policy_links': [row for row in policies if row['oid'] and row['oid'] in (props.get('issuancepolicies') or [])],
                          'evidence': evidence(g, sid, 'Properties'),
                          'requires': ['CA service grants and current publication', 'NTAuth and certificate-chain trust in the relevant forest',
                                       'certificate mapping, CA policy, issuance and authentication verification']})
    return {'principal': ref(g, principal) if principal else None, 'objects': objects, 'cas': ca_rows,
            'templates': templates, 'publications': publications, 'issuance_policies': policies,
            'limitations': ['Recorded grants exclude deny ACE/token evaluation; absent grants are not an effective denial.',
                            'Template checks are configuration matches, not verified ESC attack paths.',
                            'Collector default values are not independently verified CA observations; no certificate-chain validation.']}
