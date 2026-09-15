"""AD CS object analysis with explicit grant provenance and unknown conditions."""
from .common import evidence, identifier, membership, ref
from ..loader import ADCS_TYPES, CONTROL_RIGHTS

TEMPLATE_FIELDS = ('authenticationenabled', 'enrolleesuppliessubject', 'requiresmanagerapproval',
                   'authorizedsignatures', 'effectiveekus', 'ekus', 'certificateapplicationpolicy',
                   'schemaversion', 'nosecurityextension', 'issuancepolicies', 'applicationpolicies')
PKI_RIGHTS = CONTROL_RIGHTS | {'Enroll', 'AutoEnroll', 'ManageCA', 'ManageCertificates',
                              'WritePKINameFlag', 'WritePKIEnrollmentFlag', 'WriteOwnerRaw', 'OwnsRaw'}

CLIENT_AUTH_OIDS = {'1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4'}
SERVER_AUTH_OID = '1.3.6.1.5.5.7.3.1'
ENROLLMENT_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'
ANY_PURPOSE_OID = '2.5.29.37.0'
SID_EXTENSION_OID = '1.3.6.1.4.1.311.25.2'
DANGEROUS_OBJECT_RIGHTS = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns',
                           'WritePKINameFlag', 'WritePKIEnrollmentFlag'}

# The catalog is deliberately complete even when BloodHound JSON cannot observe a
# prerequisite.  An absent detector must never look like a negative finding.
ESC_CATALOG = {
    'ESC1': ('published template + actor enrollment + no approval/signatures + supplied subject + client authentication',
             'verify issued subject/SID extension and certificate authentication'),
    'ESC2': ('published/enrollable template with Any Purpose or no effective EKU restriction',
             'verify certificate constraints and a separate target template when using an enrollment agent'),
    'ESC3': ('published/enrollable Certificate Request Agent template',
             'verify agent restrictions, target template and authorized-signature rules'),
    'ESC4': ('selected actor has dangerous control of a certificate template object',
             'verify the specific writable attributes, publication and reversible change'),
    'ESC5': ('selected actor controls another PKI directory object',
             'verify object-specific consequence; directory control is not CA service control'),
    'ESC6': ('CA accepts request SAN attributes and actor can enroll',
             'verify CA disposition, an authentication template, issued SAN/SID and mapping'),
    'ESC7': ('selected actor has ManageCA or ManageCertificates in confirmed CA service security',
             'verify effective CA role and the exact permitted operation'),
    'ESC8': ('HTTP Web Enrollment, or HTTPS Web Enrollment without verified channel binding',
             'verify NTLM, EPA/channel binding, TLS topology and relay result'),
    'ESC9': ('published/enrollable client-authentication template disables the SID security extension',
             'verify issued certificate and current KDC/Schannel mapping enforcement'),
    'ESC10': ('weak certificate mapping configuration on the authentication target',
              'not observable in BloodHound JSON; inspect KDC/Schannel configuration and effective updates'),
    'ESC11': ('CA does not enforce encrypted MS-ICPR requests',
              'verify CA InterfaceFlags, RPC packet privacy, NTLM and relay result'),
    'ESC12': ('CA private key material can be obtained',
              'not observable in BloodHound JSON; verify key location, protection and authorized backup access'),
    'ESC13': ('published/enrollable client-authentication template links an issuance policy to a group, or actor controls its OID object',
              'verify issued policy, AMA token group and resource access'),
    'ESC14': ('actor can create or modify a weak explicit certificate mapping',
              'not safely observable from generic BloodHound ACEs; verify altSecurityIdentities and attribute-specific control'),
    'ESC15': ('published/enrollable schema-v1 template lets the enrollee supply subject',
              'verify CVE-2024-49019 patch state and issued application policies'),
    'ESC16': ('CA disables the SID security extension',
              'verify DisableExtensionList, issued certificate and current KDC/Schannel mapping enforcement'),
    'ESC17': ('published/enrollable server-authentication template lets the enrollee supply subject',
              'verify service identity use, certificate contents and application validation'),
}


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


def _state(checks, actor_selected=True):
    values = list(checks.values())
    if False in values:
        return 'not-matched'
    if values and all(value is True for value in values):
        return 'candidate'
    if not actor_selected and values and all(value is True for key, value in checks.items()
                                             if key != 'actor_can_enroll'):
        return 'configuration-candidate'
    return 'unknown'


def _assessment(esc, obj, checks, actor_selected=True, state=None, evidence_row=None):
    return {'esc': esc, 'object': obj, 'state': state or _state(checks, actor_selected),
            'checks': checks, 'evidence': (evidence_row or {}).get('evidence')}


def _selected_enrollment(enrollment, principal):
    if principal is None:
        return None
    return any(row['template_grant_found'] is True and row['ca_grant_found'] is True
               for row in enrollment)


def _collected_value(node, key='Value'):
    if not isinstance(node, dict) or node.get('Collected') is not True or node.get('FailureReason'):
        return None
    return node.get(key)


def _effective_ekus(props):
    value = props.get('effectiveekus')
    return value if isinstance(value, list) else None


def _endpoint_state(rows):
    """Return (state, checks) without treating an omitted collection as disabled."""
    if not isinstance(rows, list) or not rows:
        return 'unknown', {'endpoint_collection': None, 'relay_exposure': None}
    collected, exposed = False, False
    for row in rows:
        if not isinstance(row, dict) or row.get('Collected') is not True or row.get('FailureReason'):
            continue
        collected = True
        result = row.get('Result') if isinstance(row.get('Result'), dict) else row
        http = result.get('ADCSWebEnrollmentHTTP') is True
        https = result.get('ADCSWebEnrollmentHTTPS') is True
        epa = result.get('ADCSWebEnrollmentEPA')
        exposed = exposed or http or (https and epa is False)
    if not collected:
        return 'unknown', {'endpoint_collection': None, 'relay_exposure': None}
    return ('candidate' if exposed else 'not-matched'), {
        'endpoint_collection': True, 'relay_exposure': exposed}


def _ca_configuration_state(checks, observable=True):
    """Classify recorded CA settings without claiming live issuance behavior."""
    if not observable:
        return 'not-observable'
    values = list(checks.values())
    if False in values:
        return 'not-matched'
    if values and all(value is True for value in values):
        return 'configuration-candidate'
    return 'unknown'


def adcs(g, principal=None):
    cas = [o for o in g.objects if g.kind(o['ObjectIdentifier']) == 'enterpriseca']
    stores = [o for o in g.objects if g.kind(o['ObjectIdentifier']) == 'ntauthstore']
    objects, templates, publications, policies, assessments = [], [], [], [], []
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
        ca_row = {'ca': ref(g, sid), 'hosting_computer': ref(g, identifier(ca.get('HostingComputer'))),
                        'ntauth_thumbprint_matches': trust_matches,
                        'chain_matches': [{'thumbprint': thumbprint, 'objects': [ref(g, o['ObjectIdentifier']) for o in certificate_nodes
                            if isinstance(thumbprint, str) and thumbprint and str((o.get('Properties') or {}).get('certthumbprint', '')).casefold() == thumbprint.casefold()]}
                            for thumbprint in props.get('certchain') or []],
                        'registry': ca.get('CARegistryData'), 'http_endpoints': ca.get('HttpEnrollmentEndpoints'),
                        'grants': grants(g, ca, principal), 'evidence': evidence(g, sid, '$')}
        ca_rows.append(ca_row)
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
        ekus = _effective_ekus(props)
        if isinstance(ekus, list):
            if not ekus or '2.5.29.37.0' in ekus:
                clues.append('ESC2 template-usage candidate: no effective EKU restriction or Any Purpose')
            if '1.3.6.1.4.1.311.20.2.1' in ekus:
                clues.append('ESC3 enrollment-agent usage; target template and agent restrictions require review')
        if props.get('nosecurityextension') is True:
            clues.append('ESC9 setting: security extension disabled; mapping and authentication conditions require review')
        if any(r['right'] in {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'WritePKINameFlag', 'WritePKIEnrollmentFlag'} for r in rights):
            clues.append('ESC4 object-control candidate; specific writable attributes and issuance conditions require review')
        template_ref = ref(g, sid)
        actor_enroll = _selected_enrollment(enrollment, principal)
        gates = {'published': bool(published), 'actor_can_enroll': actor_enroll,
                 'no_manager_approval': checks['no_manager_approval'],
                 'no_authorized_signatures': checks['no_authorized_signatures']}
        any_purpose = None if ekus is None else (not ekus or ANY_PURPOSE_OID in ekus)
        enrollment_agent = None if ekus is None else ENROLLMENT_AGENT_OID in ekus
        server_auth = None if ekus is None else (SERVER_AUTH_OID in ekus or ANY_PURPOSE_OID in ekus)
        linked_group = bool([row for row in policies if row['oid'] and row['oid'] in (props.get('issuancepolicies') or [])])
        template_assessments = [
            _assessment('ESC1', template_ref, {**gates, 'enrollee_supplies_subject': subject,
                        'client_authentication': auth}, principal is not None),
            _assessment('ESC2', template_ref, {**gates, 'any_purpose_or_no_eku': any_purpose}, principal is not None),
            _assessment('ESC3', template_ref, {**gates, 'enrollment_agent': enrollment_agent}, principal is not None),
            _assessment('ESC4', template_ref, {'actor_has_template_control':
                        (any(r['right'] in DANGEROUS_OBJECT_RIGHTS for r in rights) if principal is not None else None)},
                        principal is not None),
            _assessment('ESC9', template_ref, {**gates, 'client_authentication': auth,
                        'no_security_extension': _bool(props.get('nosecurityextension'))}, principal is not None),
            _assessment('ESC13', template_ref, {**gates, 'client_authentication': auth,
                        'issuance_policy_linked_group': linked_group}, principal is not None),
            _assessment('ESC15', template_ref, {**gates, 'enrollee_supplies_subject': subject,
                        'schema_version_1': props.get('schemaversion') == 1 if type(props.get('schemaversion')) is int else None},
                        principal is not None),
            _assessment('ESC17', template_ref, {**gates, 'enrollee_supplies_subject': subject,
                        'server_authentication': server_auth}, principal is not None),
        ]
        assessments.extend(template_assessments)
        templates.append({'template': template_ref, 'settings': {k: props[k] for k in TEMPLATE_FIELDS if k in props},
                          'esc1_template_checks': checks, 'esc1_template_state': state,
                          'publication_count': len(published), 'grants': rights, 'enrollment': enrollment,
                          'clues': clues, 'esc_assessment': template_assessments,
                          'issuance_policy_links': [row for row in policies if row['oid'] and row['oid'] in (props.get('issuancepolicies') or [])],
                          'evidence': evidence(g, sid, 'Properties'),
                          'requires': ['CA service grants and current publication', 'NTAuth and certificate-chain trust in the relevant forest',
                                       'certificate mapping, CA policy, issuance and authentication verification']})

    for ca_row in ca_rows:
        registry = ca_row.get('registry') or {}
        ca_enroll = _enroll(ca_row['grants']) if principal is not None else None
        san = _collected_value(registry.get('IsUserSpecifiesSanEnabled'))
        role = (any(row['collection_confirmed'] and row['right'] in {'ManageCA', 'ManageCertificates'}
                    for row in ca_row['grants']) if principal is not None else None)
        endpoint_status, endpoint_checks = _endpoint_state(ca_row.get('http_endpoints'))
        encrypt = _collected_value(registry.get('EnforceEncryptionForRequests'))
        disabled = _collected_value(registry.get('DisabledExtensions'))
        if disabled is None:
            disabled = registry.get('DisableExtensionList')
        sid_disabled = None if not isinstance(disabled, list) else SID_EXTENSION_OID in disabled
        esc6_checks = {'actor_can_enroll': ca_enroll, 'user_specified_san': san}
        esc11_checks = {'actor_can_enroll': ca_enroll,
                        'encryption_not_enforced': (None if type(encrypt) is not bool else not encrypt)}
        esc16_checks = {'actor_can_enroll': ca_enroll, 'sid_extension_disabled': sid_disabled}
        ca_assessments = [
            _assessment('ESC6', ca_row['ca'], esc6_checks, principal is not None,
                        state=_ca_configuration_state(esc6_checks), evidence_row=ca_row),
            _assessment('ESC7', ca_row['ca'], {'actor_has_ca_role': role}, principal is not None,
                        evidence_row=ca_row),
            _assessment('ESC8', ca_row['ca'], endpoint_checks, principal is not None,
                        state=endpoint_status, evidence_row=ca_row),
            _assessment('ESC11', ca_row['ca'], esc11_checks, principal is not None,
                        state=_ca_configuration_state(esc11_checks, type(encrypt) is bool),
                        evidence_row=ca_row),
            _assessment('ESC16', ca_row['ca'], esc16_checks, principal is not None,
                        state=_ca_configuration_state(esc16_checks, isinstance(disabled, list)),
                        evidence_row=ca_row),
        ]
        ca_row['esc_assessment'] = ca_assessments
        assessments.extend(ca_assessments)

    # ESC5 is intentionally actor-specific. Listing every administrative PKI ACE
    # in an overview does not mean the environment is vulnerable.
    pki_control = []
    if principal is not None:
        for row in objects:
            if row['object']['id'] in {t['template']['id'] for t in templates}:
                continue
            pki_control.extend({'object': row['object'], 'grant': grant} for grant in row['grants']
                               if grant['right'] in DANGEROUS_OBJECT_RIGHTS)
    esc5 = _assessment('ESC5', {'id': '(PKI objects)', 'name': '(PKI objects)'},
                       {'actor_has_pki_object_control': bool(pki_control) if principal is not None else None},
                       principal is not None)
    esc5['matches'] = pki_control
    assessments.append(esc5)

    # Certipy also reports dangerous control of an issuance-policy OID object as
    # ESC13. Keep that separate from the template-to-group configuration match.
    if principal is not None:
        for row in objects:
            if g.kind(row['object']['id']) != 'issuancepolicy':
                continue
            dangerous = [grant for grant in row['grants']
                         if grant['right'] in DANGEROUS_OBJECT_RIGHTS]
            if dangerous:
                assessments.append(_assessment(
                    'ESC13', row['object'], {'actor_controls_issuance_policy_object': True},
                    evidence_row=dangerous[0]))

    # Generic BloodHound data does not prove ESC10/12/14 prerequisites. Keep
    # those explicit so users do not read a missing finding as a negative result.
    for esc in ('ESC10', 'ESC12', 'ESC14'):
        assessments.append(_assessment(esc, {'id': '(external state)', 'name': '(external state)'},
                                       {'observable_in_collection': None}, principal is not None,
                                       state='not-observable'))

    summary = []
    rank = {'candidate': 4, 'configuration-candidate': 3, 'unknown': 2,
            'not-observable': 1, 'not-matched': 0}
    for esc, (method, verify) in ESC_CATALOG.items():
        rows = [row for row in assessments if row['esc'] == esc]
        state = max((row['state'] for row in rows), key=lambda value: rank[value]) if rows else 'not-observable'
        candidates = []
        for row in rows:
            if row['state'] not in {'candidate', 'configuration-candidate'}:
                continue
            if row.get('matches'):
                candidates.extend(match['object'] for match in row['matches'])
            else:
                candidates.append(row['object'])
        summary.append({'esc': esc, 'state': state, 'candidates': candidates,
                        'method': method, 'verify': verify})

    return {'principal': ref(g, principal) if principal else None, 'objects': objects, 'cas': ca_rows,
            'templates': templates, 'publications': publications, 'issuance_policies': policies,
            'esc_summary': summary, 'esc_assessments': assessments,
            'limitations': ['Recorded grants exclude deny ACE/token evaluation; absent grants are not an effective denial.',
                            'Template checks are configuration matches, not verified ESC attack paths.',
                            'Collector default values are not independently verified CA observations; no certificate-chain validation.',
                            'not-observable means the BloodHound collection lacks a required data source; it is not a negative finding.']}
