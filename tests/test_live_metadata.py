"""Opt-in metadata preservation checks against an isolated real ClouDNS zone."""

import os
from copy import deepcopy
from itertools import product
from uuid import uuid4

import pytest
from octodns.record import Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSProvider


ENABLED = (
    os.environ.get('CLOUDNS_METADATA_TEST') == '1'
    and os.environ.get('CLOUDNS_AUTH_PASSWORD')
    and os.environ.get('CLOUDNS_TEST_DOMAIN')
    and (os.environ.get('CLOUDNS_SUB_AUTH_ID') or os.environ.get('CLOUDNS_AUTH_ID'))
)
pytestmark = pytest.mark.skipif(
    not ENABLED,
    reason='Metadata integration requires CLOUDNS_METADATA_TEST=1 and test-zone credentials',
)
SETTINGS = [flags for flags in product((False, True), repeat=3) if any(flags)]


@pytest.mark.parametrize('record_type', ('A', 'AAAA'))
@pytest.mark.parametrize('inactive,notes,failover', SETTINGS, ids=[
    'i{}-n{}-fo{}'.format(*map(int, flags)) for flags in SETTINGS
])
def test_ttl_update_preserves_metadata(record_type, inactive, notes, failover):
    """TTL updates preserve IDs, status, notes and complete failover configuration."""
    sub_id = os.environ.get('CLOUDNS_SUB_AUTH_ID')
    provider = ClouDNSProvider(
        'metadata-integration', sub_id or os.environ['CLOUDNS_AUTH_ID'],
        os.environ['CLOUDNS_AUTH_PASSWORD'], sub_auth=bool(sub_id),
    )
    client = provider._client
    client._calls_interval = .2
    domain = os.environ['CLOUDNS_TEST_DOMAIN'].rstrip('.')
    host = 'octodns-it-' + uuid4().hex
    value = '192.0.2.1' if record_type == 'A' else '2001:db8::1'
    backup = '192.0.2.2' if record_type == 'A' else '2001:db8::2'
    note = 'TTL probe: бележка & + % # ;\nsecond line'
    baseline = deepcopy(client.zone_records(domain))
    record_id = None

    def request(endpoint, **params):
        params.update({'domain-name': domain, 'record-id': record_id})
        return client._request(endpoint, params)

    try:
        result = client.record_create(domain, record_type, host, [value], rrset_ttl=300)
        record_id = str(result['data']['id'])
        if notes:
            request('dns/set-record-note', note=note)
        if failover:
            request(
                'dns/failover-activate', check_type=17,
                down_event_handler=0, up_event_handler=0,
                main_ip=value, backup_ip_1=backup,
                check_period=3600, notification_mail='-1',
            )
        if inactive:
            request('dns/change-record-status', status=0)
        before = deepcopy(client.zone_records(domain)[record_id])
        assert str(before['status']) == ('0' if inactive else '1')
        if notes:
            assert before['note'] == note
        if failover:
            assert str(before['failover']) != '0'
        note_before = request('dns/get-record-note') if notes else None
        settings_before = request('dns/failover-settings') if failover else None

        zone = Zone(domain + '.', [])
        data = getattr(provider, '_data_for_' + record_type)(record_type, [before])
        existing = Record.new(zone, host, data)
        data = deepcopy(existing.data)
        data.update(type=record_type, ttl=3600)
        desired = Record.new(zone, host, data)
        desired_before = deepcopy(desired.data)
        provider._zone_records[zone.name] = {record_id: deepcopy(before)}
        provider._apply_update(Update(existing, desired))

        after = client.zone_records(domain)[record_id]
        assert str(after['ttl']) == '3600'
        assert {k: v for k, v in before.items() if k != 'ttl'} == {
            k: v for k, v in after.items() if k != 'ttl'
        }, {k: (before.get(k), after.get(k)) for k in set(before) | set(after)
            if k != 'ttl' and before.get(k) != after.get(k)}
        assert desired.data == desired_before
        if notes:
            assert request('dns/get-record-note') == note_before
        if failover:
            settings_after = request('dns/failover-settings')
            # Monitoring may update its instantaneous check outcome during the test.
            assert {k: v for k, v in settings_before.items() if k != 'status'} == {
                k: v for k, v in settings_after.items() if k != 'status'
            }, {k: (settings_before.get(k), settings_after.get(k))
                for k in set(settings_before) | set(settings_after)
                if k != 'status' and settings_before.get(k) != settings_after.get(k)}
    finally:
        if record_id is not None:
            try:
                rows = client.zone_records(domain)
                if record_id in rows and str(rows[record_id].get('failover', 0)) != '0':
                    request('dns/failover-deactivate')
            finally:
                client.record_delete(domain, record_id)
        assert client.zone_records(domain) == baseline
