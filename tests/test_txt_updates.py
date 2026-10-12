"""Offline TXT value update regressions extending DonQuinleone's PR #29."""

from copy import deepcopy
from unittest.mock import Mock
from urllib.parse import parse_qs

import pytest
from octodns.record import Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClient, ClouDNSProvider


@pytest.mark.parametrize('old', [
    'plain text',
    ';leading;;middle;trailing;',
    r'literal\backslash;and&+%#characters',
    ';',
    'x' * 300 + ';suffix',
])
def test_txt_delete_uses_real_matcher_and_preserves_shared_state(old):
    provider = ClouDNSProvider('test', 'id', 'password')
    provider._client = Mock(spec=ClouDNSClient)
    zone = Zone('example.com.', [])
    retained, added = 'retained;value', 'added;value'
    existing = Record.new(zone, 'txt', {
        'type': 'TXT', 'ttl': 300,
        'values': [v.replace(';', r'\;') for v in [old, retained]],
    })
    desired = Record.new(zone, 'txt', {
        'type': 'TXT', 'ttl': 300,
        'values': [v.replace(';', r'\;') for v in [retained, added]],
    })
    rows = {
        '1': dict(id='1', host='txt', type='TXT', ttl='300', record=old),
        '2': dict(id='2', host='txt', type='TXT', ttl='300', record=retained),
        '3': dict(id='3', host='other', type='TXT', ttl='300', record=old),
        '4': dict(id='4', host='txt', type='SPF', ttl='300', record=old),
    }
    provider._zone_records[zone.name] = rows
    before = deepcopy((existing.data, desired.data, rows))
    provider._apply_update(Update(existing, desired))
    provider._client.record_delete.assert_called_once_with('example.com', '1')
    provider._client.record_create.assert_called_once()
    assert provider._client.record_create.call_args.kwargs['rrset_values'] == [
        added.replace(';', r'\;')
    ]
    assert (existing.data, desired.data, rows) == before


def test_txt_mock_api_apply_converges_without_mutating_desired(requests_mock):
    provider = ClouDNSProvider('test', 'id', 'password')
    old, retained, added = 'old;value;', 'retained;value;', 'new;value;'
    rows = {
        '1': dict(id='1', host='txt', type='TXT', ttl='300', status=1, record=old),
        '2': dict(id='2', host='txt', type='TXT', ttl='300', status=1, record=retained),
    }
    requests_mock.post('https://api.cloudns.net/dns/records.json',
                       json=lambda r, c: deepcopy(rows))
    requests_mock.post('https://api.cloudns.net/dns/get-zone-info.json',
                       json={'status': 'Success'})

    def delete(request, context):
        body = parse_qs(request.text)
        del rows[body['record-id'][0]]
        return {'status': 'Success'}

    def create(request, context):
        body = parse_qs(request.text)
        rows['3'] = dict(id='3', host=body['host'][0], type='TXT',
                         ttl=body['ttl'][0], status=1, record=body['record'][0])
        return {'status': 'Success'}

    requests_mock.post('https://api.cloudns.net/dns/delete-record.json', json=delete)
    requests_mock.post('https://api.cloudns.net/dns/add-record.json', json=create)
    zone = Zone('example.com.', [])
    desired = Record.new(zone, 'txt', {
        'type': 'TXT', 'ttl': 300,
        'values': [v.replace(';', r'\;') for v in [retained, added]],
    })
    zone.add_record(desired)
    before = deepcopy(desired.data)
    plan = provider.plan(zone)
    assert len(plan.changes) == 1
    assert all(r.url.endswith('/dns/records.json')
               for r in requests_mock.request_history)
    provider.apply(plan)
    assert rows['2']['record'] == retained
    assert {r['record'] for r in rows.values()} == {retained, added}
    assert desired.data == before
    assert provider.plan(zone) is None
    assert sum('delete-record' in r.url for r in requests_mock.request_history) == 1
    assert sum('add-record' in r.url for r in requests_mock.request_history) == 1
