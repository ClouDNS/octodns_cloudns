import unittest
from unittest.mock import Mock, patch
from octodns.zone import Zone
from octodns.record import Record
from octodns.provider.cloudns import (
    ClouDNSProvider,
    ClouDNSClient,
    ClouDNSClientUnknownDomainName
)

class TestClouDNSClient(unittest.TestCase):

    def setUp(self):
        self.client = ClouDNSClient('456', '123456')

    @patch('requests.Session.get')
    def test_raw_request_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Success response'
        mock_get.return_value = mock_response

        response = self.client._raw_request('dns/get-zone-info', 'domain-name=example.com')

        self.assertEqual(response.text, 'Success response')
        mock_get.assert_called_with('https://apidev.cloudns.net/dns/get-zone-info.json?auth-id=456&auth-password=123456&domain-name=example.com')

class TestClouDNSProvider(unittest.TestCase):
    def setUp(self):
        self.provider = ClouDNSProvider('test', '456', '123456')
    
    # Invalid authentication
    @patch('octodns.provider.cloudns.ClouDNSClient')
    def test_invalid_authentication(self, mock_clouDNSClient):
        # Arrange
        mock_clouDNSClient.side_effect = Exception('Invalid authentication, incorrect username, ID, or password.')

        # Act & Assert
        with self.assertRaises(Exception) as context:
            ClouDNSProvider('test', 'invalid_user_id', 'invalid_password')

        self.assertTrue('Invalid authentication' in str(context.exception))

    # Invalid Domain
    @patch('octodns.provider.cloudns.ClouDNSClient.zone_records')
    def test_populate_creates_zone_when_not_exist(self, mock_zone_records):
        provider = ClouDNSProvider('test', '456', '123456')
        zone = Zone('venkofgdge.invalidtld.', [])

        mock_zone_records.side_effect = ClouDNSClientUnknownDomainName('Missing domain name')

        with self.assertRaises(ClouDNSClientUnknownDomainName):
            provider.populate(zone)

    # Zone creation success
    @patch('octodns.provider.cloudns.ClouDNSClient.zone_create')
    def test_zone_create(self, mock_zone_create):
        provider = ClouDNSProvider('test', '456', '123456')
        zone = Zone('example552525.com.', [])

        mock_zone_create.return_value = {'status': 'Success'}
        response = provider._client.zone_create(zone.name[:-1], 'master')

        mock_zone_create.assert_called_once_with('example552525.com', 'master')
        self.assertEqual(response['status'], 'Success')
        
    @patch.object(ClouDNSClient, '_request')
    def test_zone_create_failure(self, mock_request):
        mock_request.return_value = {'status': 'Failed'}
        response = self.provider.zone_create('example.cosdm', 'master')
        
        self.assertEqual(response['status'], 'Failed')

    # Test records
    @patch('octodns.provider.cloudns.ClouDNSProvider.populate')
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


if __name__ == '__main__':
    unittest.main()
