"""Opt-in GeoDNS probes that only modify their own uniquely named rows."""

import os
from copy import deepcopy
from uuid import uuid4

import pytest
from octodns.provider import ProviderException
from octodns.record import Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClientException, ClouDNSProvider


ENABLED = (os.environ.get('CLOUDNS_GEO_TEST') == '1'
           and os.environ.get('CLOUDNS_GEO_TEST_DOMAIN')
           and os.environ.get('CLOUDNS_SUB_AUTH_ID')
           and os.environ.get('CLOUDNS_AUTH_PASSWORD'))
pytestmark = pytest.mark.skipif(not ENABLED, reason='GeoDNS live checks are opt-in')
TYPES = ('A', 'AAAA', 'ALIAS', 'CNAME', 'SRV', 'NAPTR')
CODES = ('DEFAULT', 'EUR', 'BG', 'US-1')


def assert_snapshot(actual, expected):
    # Report IDs only; never dump unrelated zone contents into a test report.
    changed = [key for key in expected if actual.get(key) != expected[key]]
    extra = sorted(set(actual) - set(expected))
    assert not changed and not extra, {'changed_ids': changed, 'extra_ids': extra}


def value_fields(record_type, index):
    if record_type == 'A':
        return {'record': '192.0.2.{}'.format(index + 1)}
    if record_type == 'AAAA':
        return {'record': '2001:db8::{}'.format(index + 1)}
    target = 'target{}.example.org.'.format(index + 1)
    if record_type == 'SRV':
        return dict(record=target, priority=10, weight=20, port=443)
    if record_type == 'NAPTR':
        return dict(order=10, pref=20, flag='S', params='SIP+D2U',
                    regexp='', replace=target)
    return {'record': target}


@pytest.fixture(scope='module')
def geo_account():
    provider = ClouDNSProvider(
        'geo-integration', os.environ['CLOUDNS_SUB_AUTH_ID'],
        os.environ['CLOUDNS_AUTH_PASSWORD'], sub_auth=True)
    client = provider._client
    # Live probes tolerate slower responses without changing provider defaults.
    client._timeout = (10, 60)
    domain = os.environ['CLOUDNS_GEO_TEST_DOMAIN'].rstrip('.')
    locations = client._request('dns/get-geodns-locations', {'domain-name': domain})
    assert set(CODES) <= {row['code'] for row in locations}
    ttls = client._request('dns/get-available-ttl', {'domain-name': domain})
    assert {300, 3600} <= {int(ttl) for ttl in ttls}
    baseline = deepcopy(client.zone_records(domain))
    return provider, domain, baseline


@pytest.mark.parametrize('record_type', TYPES)
def test_geodns_ttl_preservation_and_provider_guard(record_type, geo_account):
    provider, domain, baseline = geo_account
    client = provider._client
    host = 'octodns-geo-' + uuid4().hex
    if record_type == 'SRV':
        host = '_probe._tcp.' + host
    assert not any(row['host'] == host for row in baseline.values())
    owned = []
    omitted_differences = {}
    omitted_rejections = set()
    try:
        for index, code in enumerate(CODES):
            params = dict(value_fields(record_type, index), **{
                'domain-name': domain, 'record-type': record_type,
                'host': host, 'ttl': 300, 'geodns-code': code})
            result = client._request('dns/add-record', params)
            owned.append(str(result['data']['id']))
        rows = client.zone_records(domain)
        assert_snapshot({key: rows.get(key) for key in baseline}, baseline)
        before = {key: deepcopy(rows[key]) for key in owned}
        assert len({row['geodns-location'] for row in before.values()}) == 4
        print('{}: four locations created'.format(record_type), flush=True)

        # Exercise the provider guard using only our cached test rows.
        zone = Zone(domain + '.', [])
        sample = before[owned[0]]
        data = getattr(provider, '_data_for_' + record_type)(record_type, [sample])
        existing = Record.new(zone, host, data, lenient=True)
        data = deepcopy(existing.data)
        data.update(type=record_type, ttl=3600)
        desired = Record.new(zone, host, data, lenient=True)
        provider._zone_records[zone.name] = deepcopy(before)
        with pytest.raises(ProviderException, match='metadata|GeoDNS'):
            provider._apply_update(Update(existing, desired))
        assert_snapshot(client.zone_records(domain), rows)

        for key in owned:
            row = before[key]
            try:
                client.record_mod(domain, key, host, 3600, client.fields_from_row(row))
            except ClouDNSClientException as error:
                if str(error) != 'ClouDNS API error: There is another record for the same host.':
                    raise
                omitted_rejections.add(key)
        after = client.zone_records(domain)
        for key in owned:
            if key in omitted_rejections:
                assert after[key] == before[key]
                continue
            assert str(after[key]['ttl']) == '3600'
            differences = {field: (before[key].get(field), after[key].get(field))
                           for field in set(before[key]) | set(after[key])
                           if field != 'ttl' and before[key].get(field) != after[key].get(field)}
            if differences:
                omitted_differences[key] = differences
            assert set(differences) <= {
                'geodns-location', 'geodns-location-name', 'geodns-location-code'}
        assert_snapshot({key: after.get(key) for key in baseline}, baseline)
        print('{}: omitted-location differences: {}'.format(
            record_type, omitted_differences), flush=True)
        print('{}: omitted-location rejections: {}'.format(
            record_type, len(omitted_rejections)), flush=True)

        for key in owned:
            row = before[key]
            fields = client.fields_from_row(row)
            fields['geodns-location'] = row['geodns-location']
            client.record_mod(domain, key, host, 300, fields)
        after = client.zone_records(domain)
        for key in owned:
            assert str(after[key]['ttl']) == '300'
            assert {k: v for k, v in before[key].items() if k != 'ttl'} == {
                k: v for k, v in after[key].items() if k != 'ttl'}
        assert_snapshot({key: after.get(key) for key in baseline}, baseline)
        print('{}: explicit-location preservation passed'.format(record_type), flush=True)
        # Omitting location can reset it or reject the write. Only the explicit
        # location path establishes a safe API TTL update for GeoDNS rows.
    except Exception as error:
        print('{}: {}: {}'.format(record_type, type(error).__name__, error), flush=True)
        raise
    finally:
        # Recover a create whose response timed out by its collision-checked UUID
        # name. Existing IDs are never eligible for cleanup.
        remaining = client.zone_records(domain)
        cleanup = set(owned) | {key for key, row in remaining.items()
                               if row['host'] == host and row['type'] == record_type}
        for key in cleanup:
            assert key not in baseline
            if key in remaining:
                try:
                    client.record_delete(domain, key)
                except ClouDNSClientException as error:
                    print('Cleanup response uncertain for {}: {}'.format(key, error), flush=True)
        assert_snapshot(client.zone_records(domain), baseline)
        print('{}: baseline restored'.format(record_type), flush=True)
