import os
import unittest
from unittest.mock import Mock, patch, MagicMock
from octodns.zone import Zone
from octodns.record import Record
from octodns_cloudns import (
    ClouDNSProvider,
    ClouDNSClient,
    ClouDNSClientException,
    ClouDNSClientBadRequest,
    ClouDNSClientUnauthorized,
    ClouDNSClientForbidden,
    ClouDNSClientNotFound,
    ClouDNSClientUnknownDomainName
)

class TestClouDNSClient(unittest.TestCase):

    def setUp(self):
        self.client = ClouDNSClient('456', '123456', 'test')

    @patch('requests.Session.get')
    def test_raw_request_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Success response'
        mock_get.return_value = mock_response

        response = self.client._raw_request('dns/get-zone-info', 'domain-name=example.com')

        self.assertEqual(response.text, 'Success response')
        mock_get.assert_called_with('https://api.cloudns.net/dns/get-zone-info.json?auth-id=456&auth-password=123456&domain-name=example.com')

class TestClouDNSProvider(unittest.TestCase):
    def setUp(self):
        self.provider = ClouDNSProvider('test', '456', '123456')
    
    # Invalid authentication
    @patch('octodns_cloudns.ClouDNSClient')
    def test_invalid_authentication(self, mock_clouDNSClient):
        # Arrange
        mock_clouDNSClient.side_effect = Exception('Invalid authentication, incorrect username, ID, or password.')

        # Act & Assert
        with self.assertRaises(Exception) as context:
            ClouDNSProvider('test', 'invalid_user_id', 'invalid_password')

        self.assertTrue('Invalid authentication' in str(context.exception))

    # Invalid Domain
    @patch('octodns_cloudns.ClouDNSClient.zone_records')
    def test_populate_returns_empty_when_zone_not_exist(self, mock_zone_records):
        provider = ClouDNSProvider('test', '456', '123456')
        zone = Zone('venkofgdge.invalidtld.', [])

        mock_zone_records.side_effect = ClouDNSClientException('ClouDNS API error: Missing domain-name')

        result = provider.populate(zone)
        self.assertFalse(result)

    # Zone creation success
    @patch('octodns_cloudns.ClouDNSClient.zone_create')
    def test_zone_create(self, mock_zone_create):
        provider = ClouDNSProvider('test', '456', '123456')
        zone = Zone('example552525.com.', [])

        mock_zone_create.return_value = {'status': 'Success'}
        response = provider._client.zone_create(zone.name[:-1], 'master')

        mock_zone_create.assert_called_once_with('example552525.com', 'master')
        self.assertEqual(response['status'], 'Success')
        
    @patch.object(ClouDNSClient, '_raw_request')
    def test_zone_create_failure(self, mock_raw_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'Failed', 'statusDescription': 'Zone creation failed'}
        mock_raw_request.return_value = mock_response

        with self.assertRaises(ClouDNSClientException):
            self.provider.zone_create('example.cosdm', 'master')

    # Test records
    @patch('octodns_cloudns.ClouDNSProvider.populate')
    def test_populate_creates_A_record(self, mock_populate):
        provider = ClouDNSProvider('test', '456', '123456')
        zone_name = 'example786.com.'
        zone = Zone(zone_name, [])

        mock_populate.return_value = {'status': 'Success'}

        provider.populate(zone)

        expected_argument = zone
        actual_argument = mock_populate.call_args[0][0]
        self.assertEqual(actual_argument, expected_argument)
    
    def test_record_creation(self):
        zone_name = 'example.com.'
        zone = Zone(zone_name, [])
        
        a_record_data = {
            'type': 'A',
            'ttl': 3600,
            'values': ['1.2.3.4']
        }
        a_record = Record.new(zone, 'www', a_record_data)
        self.assertEqual(a_record.ttl, 3600)
        self.assertEqual(a_record.name, 'www')
        self.assertEqual(a_record.data['value'], '1.2.3.4')

        cname_record_data = {
            'type': 'CNAME',
            'ttl': 3600,
            'value': 'example.com.'
        }
        cname_record = Record.new(zone, 'sub', cname_record_data)
        self.assertEqual(cname_record.ttl, 3600)
        self.assertEqual(cname_record.name, 'sub')
        self.assertEqual(cname_record.data['value'], 'example.com.')
        
        mx_record_data = {
            'type': 'MX',
            'ttl': 3600,
            'values': [{'preference': 10, 'exchange': 'mailforwadrd.cloudns.net.'}]
        }
        mx_record = Record.new(zone, '', mx_record_data)
        self.assertEqual(mx_record.ttl, 3600)
        self.assertEqual(mx_record.name, '')
        self.assertEqual(str(mx_record.data['value']), "'10 mailforwadrd.cloudns.net.'")
        
        txt_record_data = {
            'type': 'TXT',
            'ttl': 3600,
            'value': 'v=spf1 -a -mx -ip:192.168.0.1'
        }
        txt_record = Record.new(zone, '', txt_record_data)
        self.assertEqual(txt_record.ttl, 3600)
        self.assertEqual(txt_record.name, '')
        self.assertEqual(txt_record.data['value'], "v=spf1 -a -mx -ip:192.168.0.1")
        
        srv_record_data = {
            'type': 'SRV',
            'ttl': 3600,
            'values': [{'priority': 10, 'weight': 50, 'port': 443, 'target': 'bigbox.example.com.'}]
        }
        srv_record = Record.new(zone, '_sip._tcp', srv_record_data)
        self.assertEqual(srv_record.ttl, 3600)
        self.assertEqual(srv_record.name, '_sip._tcp')
        self.assertEqual(str(srv_record.data['value']), "'10 50 443 bigbox.example.com.'")
        
        loc_record_data = {
            'type': 'LOC',
            'ttl': 3600,
            'values': [{"lat_degrees": 10, "lat_minutes": 11 ,"lat_seconds": 12, "lat_direction": 'S',
                           "long_degrees": 13, "long_minutes": 14, "long_seconds": 15, "long_direction": 'W',
                           "altitude": 16, "size": 17, "precision_horz": 20, "precision_vert": 21}]
        }
        loc_record = Record.new(zone, '', loc_record_data)
        self.assertEqual(loc_record.ttl, 3600)
        self.assertEqual(loc_record.name, '')
        self.assertEqual(str(loc_record.data['value']), "'10 11 12.000 S 13 14 15.000 W 16.00m 17.00m 20.00m 21.00m'")
        
        sshfp_record_data = {
            'type': 'SSHFP',
            'ttl': 3600,
            'values': [{"algorithm": 1, "fingerprint_type": 1 ,"fingerprint": '123456789abcdef67890123456789abcdef67890'}]
        }
        sshfp_record = Record.new(zone, '', sshfp_record_data)
        self.assertEqual(sshfp_record.ttl, 3600)
        self.assertEqual(sshfp_record.name, '')
        self.assertEqual(str(sshfp_record.data['value']), "'1 1 123456789abcdef67890123456789abcdef67890'")
        
        naptr_record_data = {
            'type': 'NAPTR',
            'ttl': 3600,
            'values': [{"order": 10, "preference": 100, "flags": 'S', "service": 'SIP D2U',
                            "regexp": '$!sip:info@bar.example.com!', "replacement": ''}]
        }
        naptr_record = Record.new(zone, '', naptr_record_data)
        self.assertEqual(naptr_record.ttl, 3600)
        self.assertEqual(naptr_record.name, '')
        self.assertEqual(str(naptr_record.data['value']), "'10 100 \"S\" \"SIP D2U\" \"$!sip:info@bar.example.com!\" '")
        
        tlsa_record_data = {
            'type': 'TLSA',
            'ttl': 3600,
            'values': [{"certificate_association_data": 'F34834E4BEB8DCBE0D289E3B0F3BEAB16495620088B5CE9EF766E56254B80944', "certificate_usage": 0,
                        "selector": '1', "matching_type": 1}]
        }
        tlsa_record = Record.new(zone, '_443._tcp', tlsa_record_data)
        self.assertEqual(tlsa_record.ttl, 3600)
        self.assertEqual(tlsa_record.name, '_443._tcp')
        
        geo_a_record_data = {
            'type': 'A',
            'ttl': 3600,
            'values': ['192.168.1.1'],
            'geo': {
                'AF': [
                    '2.2.3.4',
                    '2.2.3.5'
                ],
                'AS-JP': [
                    '3.2.3.4',
                    '3.2.3.5'
                ],
                'NA-US-CA': [
                    '4.2.3.4',
                    '4.2.3.5'
                ]
            }
        }

        geo_a_record = Record.new(zone, '', geo_a_record_data)
        self.assertEqual(geo_a_record.ttl, 3600)
        self.assertEqual(geo_a_record.name, '')
        self.assertEqual(str(geo_a_record.data['value']), "192.168.1.1")
        self.assertEqual(str(geo_a_record.data['geo']), "{'AF': ['2.2.3.4', '2.2.3.5'], 'AS-JP': ['3.2.3.4', '3.2.3.5'], 'NA-US-CA': ['4.2.3.4', '4.2.3.5']}")


class TestClouDNSClientErrorHandling(unittest.TestCase):
    """Tests for _request error handling: both HTTP status codes and JSON body errors."""

    def setUp(self):
        self.client = ClouDNSClient('456', '123456', 'test')

    def _mock_response(self, status_code=200, json_data=None, text=''):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.json.return_value = json_data
        response.raise_for_status = Mock()
        return response

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_raises_on_failed_status_in_json(self, mock_raw):
        """API returns 200 but JSON body has status=Failed."""
        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Invalid TTL. Choose from the list of the values we support.'}
        )
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client._request('dns/add-record', 'domain-name=example.com&record-type=A&host=test&record=1.2.3.4&ttl=120')
        self.assertIn('Invalid TTL', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_raises_on_missing_domain(self, mock_raw):
        """API returns status=Failed for missing domain-name."""
        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Missing domain-name'}
        )
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client._request('dns/get-zone-info', 'domain-name=nonexistent.invalid')
        self.assertIn('Missing domain-name', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_raises_on_unknown_error(self, mock_raw):
        """API returns status=Failed with no statusDescription."""
        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed'}
        )
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client._request('dns/add-record', '')
        self.assertIn('Unknown error', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_returns_data_on_success(self, mock_raw):
        """Successful API responses are returned as-is."""
        success_data = {'status': 'Success', 'statusDescription': 'The record was added successfully.', 'data': {'id': 12345}}
        mock_raw.return_value = self._mock_response(json_data=success_data)
        result = self.client._request('dns/add-record', '')
        self.assertEqual(result, success_data)

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_returns_list_data(self, mock_raw):
        """API responses that are lists (e.g. zone listing) pass through without error."""
        list_data = [{'name': 'example.com', 'type': 'master'}]
        mock_raw.return_value = self._mock_response(json_data=list_data)
        result = self.client._request('dns/list-zones', '')
        self.assertEqual(result, list_data)

    @patch.object(ClouDNSClient, '_raw_request')
    def test_request_returns_dict_records(self, mock_raw):
        """API responses that are dicts without status field (e.g. zone records) pass through."""
        records_data = {'1': {'id': '1', 'type': 'A', 'host': 'www', 'record': '1.2.3.4', 'ttl': '3600'}}
        mock_raw.return_value = self._mock_response(json_data=records_data)
        result = self.client._request('dns/records', '')
        self.assertEqual(result, records_data)

    @patch.object(ClouDNSClient, '_raw_request')
    def test_handle_response_400(self, mock_raw):
        """HTTP 400 raises ClouDNSClientBadRequest."""
        mock_raw.return_value = self._mock_response(status_code=400, text='Bad Request')
        with self.assertRaises(ClouDNSClientBadRequest):
            self.client._request('dns/add-record', '')

    @patch.object(ClouDNSClient, '_raw_request')
    def test_handle_response_401(self, mock_raw):
        """HTTP 401 raises ClouDNSClientUnauthorized."""
        mock_raw.return_value = self._mock_response(status_code=401, text='Unauthorized')
        with self.assertRaises(ClouDNSClientUnauthorized):
            self.client._request('dns/add-record', '')

    @patch.object(ClouDNSClient, '_raw_request')
    def test_handle_response_403(self, mock_raw):
        """HTTP 403 raises ClouDNSClientForbidden."""
        mock_raw.return_value = self._mock_response(status_code=403, text='Forbidden')
        with self.assertRaises(ClouDNSClientForbidden):
            self.client._request('dns/add-record', '')

    @patch.object(ClouDNSClient, '_raw_request')
    def test_handle_response_404(self, mock_raw):
        """HTTP 404 raises ClouDNSClientNotFound."""
        mock_raw.return_value = self._mock_response(status_code=404, text='Not Found')
        with self.assertRaises(ClouDNSClientNotFound):
            self.client._request('dns/add-record', '')

    @patch.object(ClouDNSClient, '_raw_request')
    def test_record_create_raises_on_invalid_ttl(self, mock_raw):
        """record_create with invalid TTL raises ClouDNSClientException."""
        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Invalid TTL. Choose from the list of the values we support.'}
        )
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client.record_create('example.com', 'A', 'test', ['1.2.3.4'], rrset_ttl=120)
        self.assertIn('Invalid TTL', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_record_delete_raises_on_failure(self, mock_raw):
        """record_delete raises on API failure."""
        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Invalid record ID'}
        )
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client.record_delete('example.com', '999999')
        self.assertIn('Invalid record ID', str(ctx.exception))


class TestClouDNSProviderErrorHandling(unittest.TestCase):
    """Tests for provider-level error handling during apply operations."""

    def setUp(self):
        self.provider = ClouDNSProvider('test', '456', '123456')

    def _mock_response(self, status_code=200, json_data=None):
        response = Mock()
        response.status_code = status_code
        response.json.return_value = json_data
        response.raise_for_status = Mock()
        return response

    @patch.object(ClouDNSClient, '_raw_request')
    def test_apply_creates_zone_on_missing_domain(self, mock_raw):
        """_apply creates zone when zone() returns Missing domain-name."""
        zone = Zone('newzone.com.', [])
        plan = Mock()
        plan.desired = zone
        plan.changes = []

        # First call: zone() fails; second call: zone_create() succeeds
        mock_raw.side_effect = [
            self._mock_response(json_data={'status': 'Failed', 'statusDescription': 'Missing domain-name'}),
            self._mock_response(json_data={'status': 'Success', 'statusDescription': 'Zone created'}),
        ]

        # Should not raise
        self.provider._apply(plan)

    @patch.object(ClouDNSClient, '_raw_request')
    def test_apply_reraises_non_missing_domain_error(self, mock_raw):
        """_apply re-raises errors that aren't 'Missing domain-name'."""
        zone = Zone('example.com.', [])
        plan = Mock()
        plan.desired = zone
        plan.changes = []

        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Rate limit exceeded'}
        )

        with self.assertRaises(ClouDNSClientException) as ctx:
            self.provider._apply(plan)
        self.assertIn('Rate limit exceeded', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_apply_create_raises_on_api_error(self, mock_raw):
        """_apply_create raises when record_create gets an API error."""
        zone = Zone('example.com.', [])
        record = Record.new(zone, 'www', {'type': 'A', 'ttl': 3600, 'values': ['1.2.3.4']})
        change = Mock()
        change.new = record

        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Invalid TTL. Choose from the list of the values we support.'}
        )

        with self.assertRaises(ClouDNSClientException) as ctx:
            self.provider._apply_create(change)
        self.assertIn('Invalid TTL', str(ctx.exception))

    @patch.object(ClouDNSClient, '_raw_request')
    def test_populate_handles_api_error_gracefully(self, mock_raw):
        """populate returns False when zone_records raises ClouDNSClientException."""
        zone = Zone('nonexistent.com.', [])

        mock_raw.return_value = self._mock_response(
            json_data={'status': 'Failed', 'statusDescription': 'Missing domain-name'}
        )

        result = self.provider.populate(zone)
        self.assertFalse(result)


@unittest.skipUnless(
    os.environ.get('CLOUDNS_INTEGRATION_TEST'),
    'Set CLOUDNS_INTEGRATION_TEST=1 to run integration tests'
)
class TestClouDNSIntegration(unittest.TestCase):
    """Integration tests against the real ClouDNS API.

    Run with:
        CLOUDNS_INTEGRATION_TEST=1 CLOUDNS_SUB_AUTH_ID=85055 CLOUDNS_AUTH_PASSWORD='fkc6XKR0zer*nva_vtg' python -m pytest tests/ -k Integration -v
    """

    def setUp(self):
        auth_id = os.environ.get('CLOUDNS_SUB_AUTH_ID', '85055')
        auth_password = os.environ.get('CLOUDNS_AUTH_PASSWORD', '')
        self.client = ClouDNSClient(auth_id, auth_password, 'integration-test', sub_auth=True)
        self.domain = 'argl.net'

    def test_invalid_ttl_raises(self):
        """Creating a record with TTL=120 must raise, not silently succeed."""
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client.record_create(
                self.domain, 'A', 'test-invalid-ttl',
                ['1.2.3.4'], rrset_ttl=120
            )
        self.assertIn('Invalid TTL', str(ctx.exception))

    def test_valid_record_create_and_delete(self):
        """Creating a record with a valid TTL succeeds and can be cleaned up."""
        result = self.client.record_create(
            self.domain, 'A', 'test-valid-record',
            ['1.2.3.4'], rrset_ttl=3600
        )
        self.assertEqual(result['status'], 'Success')
        record_id = result['data']['id']

        # Clean up
        delete_result = self.client.record_delete(self.domain, record_id)
        self.assertEqual(delete_result['status'], 'Success')

    def test_missing_domain_raises(self):
        """Querying a non-existent domain raises ClouDNSClientException."""
        with self.assertRaises(ClouDNSClientException) as ctx:
            self.client.zone('this-domain-does-not-exist-12345.invalid')
        self.assertIn('Missing domain-name', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
