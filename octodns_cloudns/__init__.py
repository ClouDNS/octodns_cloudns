from collections import defaultdict
from logging import getLogger
from requests import Session, RequestException
from octodns.provider import ProviderException
import logging
import time
import threading
from octodns.provider.base import BaseProvider
from octodns.record import Record, Change
from urllib.parse import quote, quote_plus
from types import SimpleNamespace
logger = logging.getLogger(__name__)

__version__ = __VERSION__ = '0.0.17'

class ClouDNSClientException(ProviderException):
    pass


class ClouDNSClientBadRequest(ClouDNSClientException):
    def __init__(self, r):
        super().__init__(r.text)


class ClouDNSClientUnauthorized(ClouDNSClientException):
    def __init__(self, r):
        super().__init__(r.text)


class ClouDNSClientForbidden(ClouDNSClientException):
    def __init__(self, r):
        super().__init__(r.text)


class ClouDNSClientNotFound(ClouDNSClientException):
    def __init__(self, r):
        super().__init__(r.text)


class ClouDNSClientUnknownDomainName(ClouDNSClientException):
    def __init__(self, msg):
        super().__init__(msg)
        
class ClouDNSClientGeoDNSNotSupported(ClouDNSClientException):
    def __init__(self, msg):
        super().__init__(msg)


class ClouDNSClient(object):
    def __init__(self, auth_id, auth_password, id, sub_auth=False):
        self.log = getLogger(f"ClouDNSProvider[{id}]")
        self._calls_per_seconds = 19 # its 20/s but leave some margin for error
        self._calls_interval = 1.0 / float(self._calls_per_seconds)
        self._api_lock = threading.Lock()
        self._api_last_call = [0.0]
        session = Session()
        session.headers.update(
            {
                "User-Agent": f"cloudns/{__version__} octodns-cloudns/{__VERSION__}",
            }
        )
        self._session = session
        if sub_auth:
            self._auth_type = 'sub-auth-id'
        else:
            self._auth_type = 'auth-id'
            
        self.auth_id = auth_id
        self.auth_password = auth_password
        
        # Currently hard-coded, but could offer XML in the future
        self._type = 'json'
        
        self._urlbase = 'https://api.cloudns.net/{}.json'
        self._timeout = (10, 30)

    def _redact(self, message):
        message = str(message)
        for secret in (self.auth_password, self.auth_id):
            if secret:
                for representation in (str(secret), quote(str(secret), safe=''),
                                       quote_plus(str(secret), safe='')):
                    message = message.replace(representation, '***')
        return message

    def _request(self, function, params=None):
        response = self._raw_request(function, params)
        self._handle_response(response)
        if self._type == 'json':
            data = response.json()
            if isinstance(data, dict) and data.get('status') == 'Failed':
                raise ClouDNSClientException(
                    'ClouDNS API error: {}'.format(self._redact(
                        data.get('statusDescription', 'Unknown error')))
                )
            return data

    def _raw_request(self, function, params=None):
        # Built-in callers pass dictionaries so requests encodes every value.
        # Keep encoded query strings accepted for existing client consumers.
        if isinstance(params, str):
            from urllib.parse import parse_qsl
            params = dict(parse_qsl(params, keep_blank_values=True))
        data = dict(params or {})
        data.update({self._auth_type: self.auth_id,
                     'auth-password': self.auth_password})
        url = self._urlbase.format(function)
        self.log.debug('Request endpoint: %s', function)

        with self._api_lock:
            now = time.monotonic()
            elapsed = now - self._api_last_call[0]
            wait = self._calls_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._api_last_call[0] = time.monotonic()
            try:
                # Do not retry writes with an ambiguous outcome.
                response = self._session.post(url, data=data,
                                              timeout=self._timeout)
            except RequestException as error:
                # requests exceptions can embed a response body or credentials.
                raise ClouDNSClientException(
                    'ClouDNS request failed at {} ({})'.format(
                        function, type(error).__name__)
                ) from None
        self.log.debug('Response status: %s', response.status_code)
        return response

    def _handle_response(self, response):
        status_code = response.status_code
        # Preserve public exception classes without including reflected secrets.
        error_response = SimpleNamespace(text=self._redact(response.text))
        if status_code == 400:
            raise ClouDNSClientBadRequest(error_response)
        elif status_code == 401:
            raise ClouDNSClientUnauthorized(error_response)
        elif status_code == 403:
            raise ClouDNSClientForbidden(error_response)
        elif status_code == 404:
            raise ClouDNSClientNotFound(error_response)
        try:
            response.raise_for_status()
        except RequestException:
            raise ClouDNSClientException(
                'ClouDNS HTTP error: {}'.format(status_code)) from None
    def checkDot(self, domain_name):
        if domain_name.endswith('.'):
            domain_name = domain_name[:-1]
        return domain_name
    
    def zone_create(self, domain_name, zone_type, master_ip=''):
        return self._request('dns/register', {
            'domain-name': domain_name, 'zone-type': zone_type,
            'master-ip': master_ip or '',
        })

    def zone(self, domain_name):
        return self._request('dns/get-zone-info', {'domain-name': domain_name})

    def zone_records(self, domain_name):
        return self._request('dns/records', {'domain-name': domain_name})

    # API write field, octoDNS value attribute, API listing field aliases.
    # The aliases follow ClouDNS's SDK write names and dns/records read names.
    _VALUE_FIELDS = {
        'MX': [('priority', 'preference', ('priority',)),
               ('record', 'exchange', ('record',))],
        'SRV': [('priority', 'priority', ('priority',)),
                ('weight', 'weight', ('weight',)),
                ('port', 'port', ('port',)),
                ('record', 'target', ('record',))],
        'SSHFP': [('algorithm', 'algorithm', ('algorithm',)),
                  ('fptype', 'fingerprint_type', ('fp_type', 'fptype')),
                  ('record', 'fingerprint', ('record',))],
        'CAA': [('caa_flag', 'flags', ('caa_flag',)),
                ('caa_type', 'tag', ('caa_type',)),
                ('caa_value', 'value', ('caa_value',))],
        'NAPTR': [('order', 'order', ('order',)),
                  ('pref', 'preference', ('pref',)),
                  ('flag', 'flags', ('flag',)),
                  ('params', 'service', ('params',)),
                  ('regexp', 'regexp', ('regexp',)),
                  ('replace', 'replacement', ('replace',))],
        'TLSA': [('record', 'certificate_association_data', ('record',)),
                 ('tlsa_usage', 'certificate_usage', ('tlsa_usage',)),
                 ('tlsa_selector', 'selector', ('tlsa_selector',)),
                 ('tlsa_matching_type', 'matching_type', ('tlsa_matching_type',))],
        'LOC': [('lat-deg', 'lat_degrees', ('lat_deg', 'lat-deg')),
                ('lat-min', 'lat_minutes', ('lat_min', 'lat-min')),
                ('lat-sec', 'lat_seconds', ('lat_sec', 'lat-sec')),
                ('lat-dir', 'lat_direction', ('lat_dir', 'lat-dir')),
                ('long-deg', 'long_degrees', ('long_deg', 'long-deg')),
                ('long-min', 'long_minutes', ('long_min', 'long-min')),
                ('long-sec', 'long_seconds', ('long_sec', 'long-sec')),
                ('long-dir', 'long_direction', ('long_dir', 'long-dir')),
                ('altitude', 'altitude', ('altitude',)),
                ('size', 'size', ('size',)),
                ('h-precision', 'precision_horz', ('h_precision', 'h-precision')),
                ('v-precision', 'precision_vert', ('v_precision', 'v-precision'))],
    }

    @classmethod
    def fields_from_row(cls, row):
        fields = {}
        mapping = cls._VALUE_FIELDS.get(row['type'],
                                       [('record', None, ('record',))])
        for field, _, aliases in mapping:
            for alias in aliases:
                if alias in row:
                    fields[field] = row[alias]
                    break
            else:
                raise ClouDNSClientException(
                    'Incomplete {} API record: missing {}'.format(
                        row['type'], aliases[0]))
        return fields

    @classmethod
    def fields_from_value(cls, rrset_type, value):
        if rrset_type in cls._VALUE_FIELDS:
            fields = {field: getattr(value, attr)
                      for field, attr, _ in cls._VALUE_FIELDS[rrset_type]}
            if rrset_type in ('MX', 'SRV'):
                fields['record'] = fields['record'].rstrip('.')
            return fields
        if rrset_type in ('TXT', 'SPF'):
            # This also works with octoDNS versions preceding TxtValue.
            value = str(value).replace(r'\;', ';')
        return {'record': value}

    def record_create(self, domain_name, rrset_type, rrset_name, rrset_values,
                      rrset_ttl=3600, geodns=False, rrset_locations=None, status=1):
        params = {
            'domain-name': domain_name, 'record-type': rrset_type,
            'host': '' if rrset_name == '@' else rrset_name,
            'ttl': rrset_ttl, 'status': status,
        }
        params.update(self.fields_from_value(rrset_type, rrset_values[0]))
        if geodns:
            for location in rrset_locations:
                self._request('dns/add-record', dict(params, **{
                    'geodns-code': location}))
            return
        return self._request('dns/add-record', params)

    def record_mod(self, domain_name, record_id, host, ttl, fields):
        params = dict(fields)
        params.update({'domain-name': domain_name, 'record-id': record_id,
                       'host': host, 'ttl': ttl})
        return self._request('dns/mod-record', params)

    def record_delete(self, domain_name, record_id):
        return self._request('dns/delete-record', {
            'domain-name': domain_name, 'record-id': record_id})


class ClouDNSProvider(BaseProvider):
    SUPPORTS_GEO = True
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        [
            "A",
            "AAAA",
            "ALIAS",
            "CAA",
            "CNAME",
            "DNAME",
            "MX",
            "NS",
            "PTR",
            "SPF",
            "SRV",
            "SSHFP",
            "TXT",
            "TLSA",
            "LOC",
            "NAPTR",
        ]
    )

    def __init__(self, id, auth_id, auth_password, sub_auth=False, *args, **kwargs):
        self.log = getLogger(f"ClouDNSProvider[{id}]")
        self.log.debug("__init__: id=%s, auth_id=***, auth_password=***, sub_auth=%s", id, sub_auth)
        super().__init__(id, *args, **kwargs)
        self._client = ClouDNSClient(auth_id, auth_password, id, sub_auth)

        self._zone_records = {}

    def _data_for_multiple(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [v["record"] + "." if v["type"] not in ["A", "AAAA", "TXT", "SPF"] else v["record"] for v in records],
        }
        
    def _data_for_TXT(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [
                (record["record"].replace(';', '\\;').rstrip('.'))
                for record in records
            ]
        }



    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_SPF = _data_for_multiple
    _data_for_NS = _data_for_multiple

    def zone(self, zone_name):
        return self._client.zone(zone_name)

    def zone_create(self, zone_name, zone_type, master_ip=None):
        return self._client.zone_create(zone_name, zone_type, master_ip=master_ip)

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    "flags": record['caa_flag'],
                    "tag": record['caa_type'],
                    "value": record['caa_value']
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_single(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "value": records[0]["record"] + ".",
        }

    _data_for_ALIAS = _data_for_single
    _data_for_CNAME = _data_for_single
    _data_for_DNAME = _data_for_single
    _data_for_PTR = _data_for_single

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            if 'priority' in record and 'record' in record:
                values.append({"preference": record['priority'], "exchange": record['record'] + '.'})
        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
            values.append({"priority": record['priority'], "weight": record['weight'] ,"port": record['port'], "target": record['record'] + '.'})
        return {"ttl": record["ttl"], "type": _type, "values": values}
    
    def _data_for_LOC(self, _type, records):
        values = []
        for record in records:
            values.append({"lat_degrees": record['lat_deg'], "lat_minutes": record['lat_min'] ,"lat_seconds": record['lat_sec'], "lat_direction": record['lat_dir'],
                           "long_degrees": record['long_deg'], "long_minutes": record['long_min'], "long_seconds": record['long_sec'], "long_direction": record['long_dir'],
                           "altitude": record['altitude'], "size": record['size'], "precision_horz": record['h_precision'], "precision_vert": record['v_precision']})
        return {"ttl": record["ttl"], "type": _type, "values": values}

    def _data_for_SSHFP(self, _type, records):
        values = []
        for record in records:
            values.append({"algorithm": record['algorithm'], "fingerprint_type": record['fp_type'] ,"fingerprint": record['record']})
        return {"ttl": records[0]["ttl"], "type": _type, "values": values}
    
    def _data_for_NAPTR(self, _type, records):
        values = []
        for record in records:
            values.append({"order": record['order'], "preference": record['pref'], "flags": record['flag'], "service": record['params'],
                            "regexp": record['regexp'], "replacement": record['replace']})
        return {"ttl": records[0]["ttl"], "type": _type, "values": values}
    
    def _data_for_TLSA(self, _type, records):
        values = []
        for record in records:
            values.append({"certificate_association_data": record['record'], "certificate_usage": record['tlsa_usage'], "selector": record['tlsa_selector'],
                            "matching_type": record['tlsa_matching_type']})
        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                rows = self._client.zone_records(zone.name[:-1])
            except ClouDNSClientException as error:
                # HTTP 404, authentication and rate limits are not missing zones.
                if str(error) == 'ClouDNS API error: Missing domain-name':
                    return {}
                raise
            if rows == []:
                rows = {}
            if not isinstance(rows, dict):
                raise ClouDNSClientException('Invalid dns/records response')
            self._zone_records[zone.name] = rows
        return self._zone_records[zone.name]

    def isGeoDNS(self, statusDescription):
        if statusDescription == 'Your plan supports only GeoDNS zones.':
            return True
        else:
            return False

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        records_data = self.zone_records(zone)

        for record_id, record in records_data.items():
            _type = record["type"]
            
            if _type not in self.SUPPORTS:
                continue

            values[record["host"]][_type].append(record)
        before = len(records_data.items())
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f"_data_for_{_type}")
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)
        exists = zone.name in self._zone_records
        self.log.debug(
            "populate:   found %s records, exists=%s",
            len(zone.records) - before,
            exists,
        )
        return exists

    def _record_name(self, name):
        return name if name else ""

    def _params_for_multiple(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [str(v) for v in record.values]
        }
        
    def _params_for_geo(self, record):
        geo_location = record.geo
        locations = []
        for code, geo_value in geo_location.items():
            continent_code = geo_value.continent_code
            country_code = geo_value.country_code
            subdivision_code = geo_value.subdivision_code
            
            if subdivision_code is not None:
                locations.append(subdivision_code)
            elif country_code is not None:
                locations.append(country_code)
            elif continent_code is not None:
                locations.append(continent_code)
            else:
                locations = 0
                
        return{
            "geodns": True,
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [str(v) for v in record.values],
            "rrset_locations": [str(v) for v in locations]
        }

    def _params_for_A_AAAA(self, record):
        if getattr(record, 'geo', False):
            return self._params_for_geo(record)
        return {
                "rrset_name": self._record_name(record.name),
                "rrset_ttl": record.ttl,
                "rrset_type": record._type,
                "rrset_values": [str(v) for v in record.values]
            }

    _params_for_A = _params_for_A_AAAA
    _params_for_AAAA = _params_for_A_AAAA
    _params_for_NS = _params_for_multiple
    _params_for_TXT = _params_for_multiple
    _params_for_SPF = _params_for_multiple

    def _params_for_CAA(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [f'{v.flags} {v.tag} "{v.value}"' for v in record.values],
        }

    def _params_for_single(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [record.value],
        }

    _params_for_ALIAS = _params_for_single
    _params_for_CNAME = _params_for_single
    _params_for_DNAME = _params_for_single
    _params_for_PTR = _params_for_single

    def _params_for_MX(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [f"{v.preference} {v.exchange}" for v in record.values],
        }

    def _params_for_SRV(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [
                f"{v.priority} {v.weight} {v.port} {v.target}" for v in record.values
            ],
        }

    def _params_for_SSHFP(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [
                f"{v.algorithm} {v.fingerprint_type} " f"{v.fingerprint}"
                for v in record.values
            ],
        }
        
    def _params_for_LOC(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [
                f"{v.lat_degrees} {v.lat_minutes} {v.lat_seconds} {v.lat_direction} "
                f"{v.long_degrees} {v.long_minutes} {v.long_seconds} {v.long_direction} {v.altitude} {v.size} {v.precision_horz} {v.precision_vert} "
                for v in record.values
            ],
        }
        
    def _params_for_NAPTR(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [
                f"{v.order} {v.preference} {v.flags} {v.service} {v.regexp} {v.replacement}"
                for v in record.values
            ],
        }
        
    def _params_for_TLSA(self, record):
        return {
            "rrset_name": self._record_name(record.name),
            "rrset_ttl": record.ttl,
            "rrset_type": record._type,
            "rrset_values": [
                f"{v.certificate_association_data} {v.certificate_usage} {v.selector} {v.matching_type}"
                for v in record.values
            ],
        }

    def _apply_create(self, change):
        new = change.new      
        if hasattr(new, 'values'):
            for value in new.values:
                data = getattr(self, f"_params_for_{new._type}")(new)
                if ('rrset_values' in data):
                    data['rrset_values'] = [value]
                    self._client.record_create(new.zone.name[:-1], **data)
                else:
                    data = getattr(self, f"_params_for_{new._type}")(new)
        else:
            data = getattr(self, f"_params_for_{new._type}")(new)
            self._client.record_create(new.zone.name[:-1], **data)

    @staticmethod
    def _is_ttl_only(change):
        old = dict(change.existing.data)
        new = dict(change.new.data)
        old.pop('ttl', None)
        new.pop('ttl', None)
        return old == new and change.existing.ttl != change.new.ttl

    @staticmethod
    def _validate_mod_row(row, existing):
        # Preserve these features until live API probes establish mod semantics.
        if (str(row.get('status', 1)) != '1'
                or str(row.get('failover', 0)) != '0'
                or row.get('notes')
                or any(row.get(key) for key in (
                    'geodns-location', 'geodns-code', 'geodns-location-code'))):
            raise ProviderException(
                'TTL update requires an unmonitored, active, non-GeoDNS '
                'record without notes: {} {}'.format(existing.name, existing._type))

    def _ttl_operations(self, change):
        existing = change.existing
        if getattr(existing, 'geo', None) or getattr(change.new, 'geo', None):
            raise ProviderException('TTL-only updates of GeoDNS are not supported')
        operations = []
        for record_id, row in self.zone_records(existing.zone).items():
            if row['host'] != existing.name or row['type'] != existing._type:
                continue
            # mod-record preservation of these settings requires live probes.
            # Reject the whole rrset before issuing its first write.
            self._validate_mod_row(row, existing)
            fields = ClouDNSClient.fields_from_row(row)
            if int(row['ttl']) != change.new.ttl:
                operations.append((row, row.get('id', record_id), fields))
        if not operations:
            raise ProviderException(
                'Update produced no API operations: {} {}'.format(
                    existing.fqdn, existing._type))
        return operations

    def _apply_update(self, change):
        existing = change.existing
        zone = existing.zone
        if self._is_ttl_only(change):
            for row, record_id, fields in self._ttl_operations(change):
                self._client.record_mod(zone.name[:-1], record_id, row['host'],
                                        change.new.ttl, fields)
                row['ttl'] = str(change.new.ttl)
            return

        # Keep complex value reconciliation for 0.1.0. A simultaneous TTL
        # change must not succeed while leaving unchanged values at the old TTL.
        if existing.ttl != change.new.ttl:
            raise ProviderException(
                'Change TTL and values separately until update-based reconciliation')

        if not hasattr(existing, 'values'):
            records = [row for row in self.zone_records(zone).values()
                       if row['host'] == existing.name
                       and row['type'] == existing._type]
            if not records:
                raise ProviderException('No API records matched the single-value update')
            for row in records:
                self._validate_mod_row(row, existing)
            fields = ClouDNSClient.fields_from_value(
                change.new._type, change.new.value)
            for row in records:
                self._client.record_mod(zone.name[:-1], row['id'], row['host'],
                                        change.new.ttl, fields)
            return

        records = self._records_are_same(existing)
        try:
            to_delete = set(existing.values).difference(change.new.values)
            to_create = set(change.new.values).difference(existing.values)
        except TypeError:
            replace_all = True
        else:
            replace_all = any('record' not in record for record in records)

        if replace_all:
            for record in records:
                self._client.record_delete(zone.name[:-1], record['id'])
            self._apply_create(change)
            return

        operations = 0
        for record in records:
            if record['record'] in to_delete:
                self._client.record_delete(zone.name[:-1], record['id'])
                operations += 1

        if to_create:
            # Do not modify change.new: it is shared with plan.desired/targets.
            new = change.new.copy()
            new.values = sorted(to_create)
            self._apply_create(Change(existing=existing, new=new))
            operations += len(to_create)
        if not operations:
            raise ProviderException(
                'Update produced no API operations: {} {}'.format(
                    existing.fqdn, existing._type))

    def records_are_same(self, existing):
        records = self._records_are_same(existing)
        return [record_id['id'] for record_id in records if 'id' in record_id]

    def _records_are_same(self, existing):
        zone = existing.zone
        records = []
        for record_id, record in self.zone_records(zone).items():
                if existing._type == 'NAPTR' and record['type'] == 'NAPTR':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.order == int(record['order'])
                            and value.preference == int(record['pref'])
                            and value.flags == record['flag']
                        ):
                            records.append(record)
                elif existing._type == 'SSHFP' and record['type'] == 'SSHFP':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.fingerprint_type == int(record['fp_type'])
                            and value.algorithm == int(record['algorithm'])
                            and value.fingerprint == record['record']
                        ):
                            records.append(record)
                elif existing._type == 'SRV' and record['type'] == 'SRV':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.priority == int(record['priority'])
                            and value.weight == int(record['weight'])
                            and value.port == int(record['port'])
                            and (value.target == record['record'] or value.target == record['record']+'.')
                        ):
                            records.append(record)
                elif existing._type == 'CAA' and record['type'] == 'CAA':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.flags == record['caa_flag']
                            and value.tag == record['caa_type']
                            and value.value == record['caa_value']
                        ):
                            records.append(record)
                elif existing._type == 'MX' and record['type'] == 'MX':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.preference == int(record['priority'])
                            and (value.exchange == record['record'] or value.exchange == (record['record']+'.') )
                        ):
                            records.append(record)
                        
                elif existing._type == 'LOC' and record['type'] == 'LOC':
                    for value in existing.values:
                        if (
                            existing.name == record['host']
                            and value.lat_degrees == record['lat_deg']
                            and value.lat_minutes == record['lat_min']
                            and value.lat_seconds == record['lat_sec']
                            and value.lat_direction == record['lat_dir']
                            and value.long_degrees == record['long_deg']
                            and value.long_minutes == record['long_min']
                            and value.long_seconds == record['long_sec']
                            and value.long_direction == record['long_dir']
                            and value.altitude == record['altitude']
                            and value.size == record['size']
                            and value.precision_horz == record['h_precision']
                            and value.precision_vert == record['v_precision']
                        ):
                            records.append(record)
                elif existing._type == 'CNAME' and record['type'] == 'CNAME':
                    if (
                            existing.name == record['host']
                            and existing._type == record['type']
                            and (existing.value == record['record'] or existing.value == (record['record']+'.'))
                    ):
                        records.append(record)
                elif existing._type == 'PTR' and record['type'] == 'PTR':
                    if (
                            existing.name == record['host']
                            and existing._type == record['type']
                            and (existing.value == record['record'] or existing.value == (record['record']+'.'))
                    ):
                        records.append(record)
                elif existing._type == 'TXT' and record['type'] == 'TXT':
                    for value in existing.values:
                        txt_value = value.replace('\\;', ';')
                        if (
                            existing.name == record['host']
                            and existing._type == record['type']
                            and (txt_value == record['record'])
                        ):
                            records.append(record)

                else:
                    if (record == 'Failed' or record == 'Missing domain-name'):
                        continue
                    
                    if hasattr(existing, 'value'):
                        if (
                            existing.name == record['host']
                            and existing._type == record['type']
                            and existing.value == record['record']
                        ):
                            records.append(record)
                    elif hasattr(existing, 'values'):
                        for value in existing.values:
                            if (
                                existing.name == record['host']
                                and existing._type == record['type']
                                and (value == record['record'] or value == (record['record']+'.'))
                            ):
                                records.append(record)
        return records

    def _apply_delete(self, change):
        existing = change.existing
        zone = existing.zone
        record_ids = self.records_are_same(existing)
        
        for record_id in record_ids:
            self._client.record_delete(zone.name[:-1], record_id)

    def _apply(self, plan):
        desired = plan.desired
        
        changes = plan.changes
        zone_name = desired.name[:-1]
        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        try:
            for change in changes:
                if change.__class__.__name__ == 'Update':
                    if self._is_ttl_only(change):
                        self._ttl_operations(change)
                    elif change.existing.ttl != change.new.ttl:
                        raise ProviderException(
                            'Change TTL and values separately until '
                            'update-based reconciliation')
            # Does the zone actually exist?
            try:
                zone = self._client.zone(zone_name)
            except ClouDNSClientException as e:
                if 'Missing domain-name' not in str(e):
                    raise

                geodns_only = self.isGeoDNS(str(e))
                zone = self._client.zone_create(zone_name, 'geodns' if geodns_only else 'master')
                self.log.info("_apply: zone has been successfully created")

            for change in changes:
                class_name = change.__class__.__name__
                getattr(self, f"_apply_{class_name.lower()}")(change)

        finally:
            self._zone_records.pop(desired.name, None)
