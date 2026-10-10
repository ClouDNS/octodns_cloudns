"""Offline regression tests for the 0.0.18 hotfix (issue #25)."""

from copy import deepcopy
from unittest.mock import Mock, call
from urllib.parse import parse_qs

import pytest
import requests
from octodns.provider import ProviderException
from octodns.provider.plan import Plan
from octodns.record import Create, Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClient, ClouDNSClientException, ClouDNSProvider


# Rows model dns/records: scalar fields are strings, status is an integer.
ROWS = {
    'A': {'record': '192.0.2.1'},
    'AAAA': {'record': '2001:db8::1'},
    'ALIAS': {'record': 'alias.example.net'},
    'CNAME': {'record': 'target.example.net'},
    'DNAME': {'record': 'subtree.example.net'},
    'NS': {'record': 'ns1.example.net'},
    'PTR': {'record': 'ptr.example.net'},
    'TXT': {'record': 'a&b+c%2B#suffix;.'},
    'SPF': {'record': 'v=spf1 -all'},
    'MX': {'record': 'mail.example.net', 'priority': '10'},
    'SRV': {
        'record': 'sip.example.net',
        'priority': '10',
        'weight': '5',
        'port': '443',
    },
    'SSHFP': {
        'record': '0123456789abcdef0123456789abcdef01234567',
        'algorithm': '1',
        'fp_type': '1',
    },
    'CAA': {'caa_flag': '0', 'caa_type': 'issue', 'caa_value': 'letsencrypt.org'},
    'NAPTR': {
        'order': '10',
        'pref': '20',
        'flag': 'S',
        'params': 'SIP+D2U',
        'regexp': '',
        'replace': '_sip._udp.example.net.',
    },
    'TLSA': {
        'record': '0123456789abcdef' * 4,
        'tlsa_usage': '3',
        'tlsa_selector': '1',
        'tlsa_matching_type': '1',
    },
    'LOC': {
        'lat_deg': '42',
        'lat_min': '1',
        'lat_sec': '1.5',
        'lat_dir': 'N',
        'long_deg': '23',
        'long_min': '2',
        'long_sec': '2.5',
        'long_dir': 'E',
        'altitude': '500',
        'size': '1',
        'h_precision': '10',
        'v_precision': '1',
    },
}

# Expected request names are independent of the client's serializer table.
WRITE_ALIASES = {
    'fp_type': 'fptype',
    'lat_deg': 'lat-deg',
    'lat_min': 'lat-min',
    'lat_sec': 'lat-sec',
    'lat_dir': 'lat-dir',
    'long_deg': 'long-deg',
    'long_min': 'long-min',
    'long_sec': 'long-sec',
    'long_dir': 'long-dir',
    'h_precision': 'h-precision',
    'v_precision': 'v-precision',
}


def provider_and_change(record_type='A', count=1, host=None):
    if record_type not in Record._CLASSES:
        pytest.skip('Record type is unavailable in this octoDNS version')
    provider = ClouDNSProvider('ttl-test', 'test-id', 'test-password')
    zone = Zone('example.com.', [])
    host = (
        host
        if host is not None
        else (
            ''
            if record_type == 'ALIAS'
            else '_443._tcp'
            if record_type == 'TLSA'
            else '_sip._tcp'
            if record_type == 'SRV'
            else 'www'
        )
    )
    rows = {
        str(i): dict(
            deepcopy(ROWS[record_type]),
            id=str(i),
            type=record_type,
            host=host,
            ttl='300',
            status=1,
            failover='0',
        )
        for i in range(1, count + 1)
    }
    provider._zone_records[zone.name] = rows
    data = getattr(provider, '_data_for_' + record_type)(
        record_type, list(rows.values())
    )
    old = Record.new(zone, host, data, lenient=True)
    data = deepcopy(old.data)
    data['type'] = record_type
    data['ttl'] = 3600
    desired = Record.new(zone, host, data, lenient=True)
    provider._client = Mock(spec=ClouDNSClient)
    return provider, Update(old, desired), rows


@pytest.mark.parametrize('record_type', sorted(ROWS))
def test_ttl_only_modifies_every_row_without_value_matcher(record_type):
    provider, change, rows = provider_and_change(record_type, count=2)
    before = deepcopy(change.new.data)
    old_rows = deepcopy(rows)
    provider._records_are_same = Mock(side_effect=AssertionError('legacy matcher used'))
    provider._apply(Plan(change.existing.zone, change.new.zone, [change], True))
    assert provider._client.record_mod.call_args_list == [
        call(
            'example.com',
            row['id'],
            row['host'],
            3600,
            ClouDNSClient.fields_from_row(row),
        )
        for row in old_rows.values()
    ]
    provider._client.record_create.assert_not_called()
    provider._client.record_delete.assert_not_called()
    assert change.new.data == before
    assert change.new.zone.name not in provider._zone_records


def test_root_ns_and_unrelated_rows():
    provider, change, rows = provider_and_change('NS', count=2, host='')
    rows['2']['record'] = 'ns2.example.net'
    rows['3'] = dict(rows['1'], id='3', host='other')
    rows['4'] = dict(rows['1'], id='4', type='TXT')
    provider._apply_update(change)
    assert [c.args[1] for c in provider._client.record_mod.call_args_list] == ['1', '2']


def test_ttl_only_a_with_real_matching_does_not_silently_succeed():
    provider, change, _ = provider_and_change()
    provider._apply_update(change)
    assert provider._client.mock_calls == [
        call.record_mod('example.com', '1', 'www', 3600, {'record': '192.0.2.1'})
    ]


def test_two_distinct_a_values_both_keep_their_ids_and_values():
    provider, change, rows = provider_and_change(count=2)
    rows['2']['record'] = '192.0.2.2'
    old = Record.new(
        change.existing.zone,
        'www',
        {'type': 'A', 'ttl': 300, 'values': ['192.0.2.1', '192.0.2.2']},
    )
    new = Record.new(
        change.new.zone,
        'www',
        {'type': 'A', 'ttl': 3600, 'values': ['192.0.2.1', '192.0.2.2']},
    )
    provider._apply_update(Update(old, new))
    assert provider._client.mock_calls == [
        call.record_mod('example.com', '1', 'www', 3600, {'record': '192.0.2.1'}),
        call.record_mod('example.com', '2', 'www', 3600, {'record': '192.0.2.2'}),
    ]


def test_only_rows_with_different_ttl_are_modified():
    provider, change, rows = provider_and_change(count=2)
    rows['2']['ttl'] = '3600'
    provider._apply_update(change)
    assert provider._client.record_mod.call_count == 1


@pytest.mark.parametrize(
    'problem',
    [
        {'status': 0},
        {'failover': '1'},
        {'notes': 'operator note'},
        {'geodns-location': 'US'},
        {'geodns-code': 'US'},
        {'geodns-location-code': 'US'},
    ],
)
def test_unverified_metadata_is_rejected_before_any_write(problem):
    provider, change, rows = provider_and_change(count=2)
    rows['2'].update(problem)
    plan = Plan(change.existing.zone, change.new.zone, [change], True)
    with pytest.raises(ProviderException, match='TTL update requires'):
        provider._apply(plan)
    assert provider._client.mock_calls == []
    assert provider._zone_records == {}


def test_incomplete_row_blocks_entire_rrset():
    provider, change, rows = provider_and_change('CAA', count=2)
    del rows['2']['caa_value']
    with pytest.raises(ClouDNSClientException, match='missing caa_value'):
        provider._apply_update(change)
    assert provider._client.mock_calls == []


def test_api_map_key_is_used_when_row_id_is_omitted():
    provider, change, rows = provider_and_change()
    del rows['1']['id']
    provider._apply_update(change)
    assert provider._client.record_mod.call_args.args[1] == '1'


@pytest.mark.parametrize(
    'rows', [{}, {'1': dict(ROWS['A'], id='1', type='A', host='www', ttl='3600')}]
)
def test_zero_operation_update_fails(rows):
    provider, change, _ = provider_and_change()
    provider._zone_records[change.existing.zone.name] = rows
    with pytest.raises(ProviderException, match='no API operations'):
        provider._apply_update(change)
    provider._client.record_mod.assert_not_called()


def test_partial_api_failure_is_loud_and_clears_cache():
    provider, change, _ = provider_and_change(count=2)
    provider._client.record_mod.side_effect = [
        {'status': 'Success'},
        ClouDNSClientException('Invalid TTL'),
    ]
    with pytest.raises(ClouDNSClientException, match='Invalid TTL'):
        provider._apply(Plan(change.existing.zone, change.new.zone, [change], True))
    assert provider._zone_records == {}
    provider._client.record_delete.assert_not_called()
    provider._client.record_create.assert_not_called()


def test_value_diff_does_not_mutate_desired_for_second_target():
    provider, change, rows = provider_and_change()
    data = dict(change.new.data, type='A', ttl=300, values=['192.0.2.1', '192.0.2.2'])
    data.pop('value', None)
    change = Update(change.existing, Record.new(change.new.zone, 'www', data))
    before = deepcopy(change.new.data)
    provider._apply_update(change)
    assert change.new.data == before
    provider._client.record_create.assert_called_once()
    assert provider._client.record_create.call_args.kwargs['rrset_values'] == [
        '192.0.2.2'
    ]


@pytest.mark.parametrize('record_type', ['CNAME', 'ALIAS', 'DNAME'])
def test_single_value_update_uses_mod(record_type):
    provider, change, _ = provider_and_change(record_type)
    data = dict(change.new.data, type=record_type, ttl=300, value='new.example.net.')
    change = Update(
        change.existing, Record.new(change.new.zone, change.existing.name, data)
    )
    provider._apply_update(change)
    provider._client.record_mod.assert_called_once_with(
        'example.com', '1', change.existing.name, 300, {'record': 'new.example.net.'}
    )
    provider._client.record_create.assert_not_called()
    provider._client.record_delete.assert_not_called()


def test_ttl_and_values_change_is_rejected_before_other_plan_writes():
    provider, change, _ = provider_and_change()
    new = Record.new(
        change.new.zone, 'www', {'type': 'A', 'ttl': 3600, 'value': '192.0.2.2'}
    )
    create = Create(
        Record.new(new.zone, 'other', {'type': 'A', 'ttl': 300, 'value': '192.0.2.3'})
    )
    with pytest.raises(ProviderException, match='Change TTL and values separately'):
        provider._apply(
            Plan(
                change.existing.zone,
                new.zone,
                [create, Update(change.existing, new)],
                True,
            )
        )
    assert provider._client.mock_calls == []


@pytest.mark.parametrize(
    'error',
    [
        ClouDNSClientException('ClouDNS API error: Invalid authentication'),
        ClouDNSClientException('ClouDNS API error: Request blocked.'),
        ClouDNSClientException('ClouDNS request failed at dns/records (Timeout)'),
    ],
)
def test_populate_propagates_api_errors(error):
    provider = ClouDNSProvider('test', 'id', 'password')
    provider._client = Mock(spec=ClouDNSClient)
    provider._client.zone_records.side_effect = error
    with pytest.raises(ClouDNSClientException):
        provider.populate(Zone('example.com.', []))


def test_empty_existing_zone_is_cached_and_not_missing():
    provider = ClouDNSProvider('test', 'id', 'password')
    provider._client = Mock(spec=ClouDNSClient)
    provider._client.zone_records.return_value = []
    zone = Zone('example.com.', [])
    assert provider.populate(zone) is True
    assert provider.zone_records(zone) == {}
    provider._client.zone_records.assert_called_once()


@pytest.mark.parametrize('record_type', sorted(ROWS))
def test_mod_posts_all_type_fields_and_uses_record_id(record_type, requests_mock):
    client = ClouDNSClient('sub-user', 'secret&+%#', 'test', sub_auth=True)
    url = 'https://api.cloudns.net/dns/mod-record.json'
    requests_mock.post(url, json={'status': 'Success'})
    fields = client.fields_from_row(dict(ROWS[record_type], type=record_type))
    assert fields == {
        WRITE_ALIASES.get(key, key): value for key, value in ROWS[record_type].items()
    }
    client.record_mod('example.com', '987', 'www', 3600, fields)
    request = requests_mock.last_request
    body = parse_qs(request.text, keep_blank_values=True)
    assert request.url == url
    assert body['sub-auth-id'] == ['sub-user']
    assert body['auth-password'] == ['secret&+%#']
    assert body['record-id'] == ['987']
    assert body['ttl'] == ['3600']
    for key, value in fields.items():
        assert body[key] == [str(value)]
    assert 'Authorization' not in request.headers


@pytest.mark.parametrize(
    'record_type,value',
    [
        ('TXT', r'a&b+c%2B#fragment\;.'),
        ('CAA', Mock(flags=0, tag='issue', value='a&b+c%2B#fragment')),
        (
            'NAPTR',
            Mock(
                order=1,
                preference=2,
                flags='U',
                service='x+y',
                regexp='!^.*$!a&b+c%2B#fragment!',
                replacement='.',
            ),
        ),
    ],
)
def test_create_encodes_special_characters(record_type, value, requests_mock):
    client = ClouDNSClient('id', 'password', 'test')
    requests_mock.post(
        'https://api.cloudns.net/dns/add-record.json', json={'status': 'Success'}
    )
    client.record_create('example.com', record_type, 'www', [value])
    body = parse_qs(requests_mock.last_request.text, keep_blank_values=True)
    expected = ClouDNSClient.fields_from_value(record_type, value)
    assert all(body[key] == [str(val)] for key, val in expected.items())
    if record_type == 'TXT':
        assert body['record'] == ['a&b+c%2B#fragment;.']


def test_secret_is_absent_from_debug_logs_and_error(caplog, requests_mock):
    client = ClouDNSClient('sub-user', 'secret&+%#', 'test', sub_auth=True)
    requests_mock.post(
        'https://api.cloudns.net/dns/mod-record.json',
        json={
            'status': 'Failed',
            'statusDescription': 'Rejected secret&+%# for sub-user',
        },
    )
    caplog.set_level('DEBUG', logger='ClouDNSProvider[test]')
    with pytest.raises(ClouDNSClientException) as error:
        client.record_mod('example.com', '1', 'www', 3600, {'record': '192.0.2.1'})
    assert 'secret&+%#' not in caplog.text + str(error.value)
    assert 'sub-user' not in caplog.text + str(error.value)
    assert 'Request endpoint: dns/mod-record' in caplog.text


def test_transport_timeout_is_bounded_and_not_retried():
    client = ClouDNSClient('id', 'password', 'test')
    client._session = Mock()
    client._session.post.side_effect = requests.Timeout('password')
    with pytest.raises(ClouDNSClientException, match='Timeout') as error:
        client.record_delete('example.com', '1')
    assert 'password' not in str(error.value)
    assert client._session.post.call_count == 1
    assert client._session.post.call_args.kwargs['timeout'] == (10, 30)


def test_round_trip_apply_converges_and_dry_run_does_not_write(requests_mock):
    provider = ClouDNSProvider('test', 'id', 'password')
    rows = {'1': dict(ROWS['A'], id='1', type='A', host='www', ttl='300', status=1)}
    requests_mock.post(
        'https://api.cloudns.net/dns/records.json', json=lambda r, c: deepcopy(rows)
    )
    requests_mock.post(
        'https://api.cloudns.net/dns/get-zone-info.json', json={'status': 'Success'}
    )

    def modify(request, context):
        body = parse_qs(request.text)
        row = rows[body['record-id'][0]]
        row['ttl'] = body['ttl'][0]
        row['record'] = body['record'][0]
        return {'status': 'Success'}

    requests_mock.post('https://api.cloudns.net/dns/mod-record.json', json=modify)
    zone = Zone('example.com.', [])
    zone.add_record(
        Record.new(zone, 'www', {'type': 'A', 'ttl': 3600, 'value': '192.0.2.1'})
    )
    plan = provider.plan(zone)
    assert len(plan.changes) == 1
    assert all(
        r.url.endswith('/dns/records.json') for r in requests_mock.request_history
    )
    before = deepcopy(plan.desired.records.copy().pop().data)
    provider.apply(plan)
    assert rows['1']['ttl'] == '3600'
    assert plan.desired.records.copy().pop().data == before
    assert provider.plan(zone) is None
    assert not any(
        'add-record' in r.url or 'delete-record' in r.url
        for r in requests_mock.request_history
    )
