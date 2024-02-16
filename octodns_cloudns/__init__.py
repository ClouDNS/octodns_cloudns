from collections import defaultdict
from logging import getLogger
from requests import Session
from octodns.provider import ProviderException
import logging
from octodns.provider.base import BaseProvider
from octodns.record import Record
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

__version__ = __VERSION__ = '0.0.1'

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
    def __init__(self, auth_id, auth_password, sub_auth=False):
        session = Session()
        session.headers.update(
            {
                "Authorization": f"Bearer {auth_id}:{auth_password}",
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
        
        self._urlbase = 'https://apidev.cloudns.net/{0}.{1}?{4}={2}&auth-password={3}&{0}'.format(
            '{}', self._type, self.auth_id, self.auth_password, self._auth_type)

        
    def _request(self, function, params=''):
        response = self._raw_request(function, params)
        if self._type == 'json':
            return response.json()
        
    def _raw_request(self, function, params=''):
        url = self._urlbase.format(function, params)
        print(url)
        logger.debug(f"Request URL: {url}")
        response = self._session.get(url)
        logger.debug(f"Request Response: {response.text}")
        return response
        
    def _handle_response(self, response):
        status_code = response.status_code
        if status_code == 400:
            raise ClouDNSClientBadRequest(response)
        elif status_code == 401:
            raise ClouDNSClientUnauthorized(response)
        elif status_code == 403:
            raise ClouDNSClientForbidden(response)
        elif status_code == 404:
            raise ClouDNSClientNotFound(response)
        response.raise_for_status()
    def checkDot(self, domain_name):
        if domain_name.endswith('.'):
            domain_name = domain_name[:-1]
        return domain_name
    
    def zone_create(self, domain_name, zone_type, master_ip=''):
        params = 'domain-name={}&zone-type={}&master-ip={}'.format(domain_name, zone_type, master_ip)
        return self._request('dns/register', params)
    
    def zone(self, domain_name):
        params = 'domain-name={}'.format(domain_name)
        return self._request('dns/get-zone-info', params)
    
    def zone_records(self, domain_name):
        params = 'domain-name={}'.format(domain_name)
        return self._request('dns/records', params)

    def record_create(self, domain_name, rrset_type, rrset_name, rrset_values, rrset_ttl=3600, geodns=False, rrset_locations = None, status=1):
        if (rrset_name == '@'):
            rrset_name = ''
            
        params = 'domain-name={}&record-type={}&host={}&ttl={}&status={}'.format(
            domain_name, rrset_type, rrset_name, rrset_ttl, status)

        single_types = ['CNAME', 'A', 'AAAA', 'DNAME', 'ALIAS', 'NS', 'PTR', 'SPF', 'TXT']
        if rrset_type in single_types:
            params += '&record={}'.format(rrset_values[0])
            
        if(geodns is True):
            for location in rrset_locations:
                params += '&geodns-code={}'.format(location)
                self._request('dns/add-record', params)
            return
        
        if rrset_type == 'MX':
            values = rrset_values[0]
            
            priority = values.preference
            record = values.exchange
            
            record = self.checkDot(record)
            params += '&priority={}&record={}'.format(priority,record)
            
        if rrset_type == 'SSHFP':
            sshfp_value = rrset_values[0]
            algorithm = sshfp_value.algorithm
            fptype = sshfp_value.fingerprint_type
            record = sshfp_value.fingerprint

            params += '&algorithm={}&fptype={}&record={}'.format(algorithm, fptype, record)

        if rrset_type == 'SRV':
            values = rrset_values[0]
            
            srv_value = rrset_values[0]
            priority = srv_value.priority
            weight = srv_value.weight
            port = srv_value.port
            record = srv_value.target
            
            params += '&priority={}&weight={}&port={}&record={}'.format(priority, weight, port,record)
            
        if rrset_type == 'CAA':
            values = rrset_values[0]
            
            caa_value = rrset_values[0]
            flag = caa_value.flags
            caa_type = caa_value.tag
            caa_value = caa_value.value
            params += '&flag={}&caa_type={}&caa_value={}'.format(flag, caa_type, caa_value)
            
        if rrset_type == 'LOC':
            values = rrset_values[0]

            loc_value = rrset_values[0]
            lat_deg = loc_value.lat_degrees
            lat_min = loc_value.lat_minutes
            lat_sec = loc_value.lat_seconds
            lat_dir = loc_value.lat_direction
            long_deg = loc_value.long_degrees
            long_min = loc_value.long_minutes
            long_sec = loc_value.long_seconds
            long_dir = loc_value.long_direction
            altitude = loc_value.altitude
            size = loc_value.size
            h_precision = loc_value.precision_horz
            v_precision = loc_value.precision_vert
            
            params += '&lat-deg={}&lat-min={}&lat-sec={}&lat-dir={}&long-deg={}&long-min={}&long-sec={}&long-dir={}&altitude={}&size={}&h-precision={}&v-precision={}'.format(
                lat_deg, lat_min, lat_sec, lat_dir, long_deg, long_min, long_sec, long_dir, altitude, size, h_precision, v_precision)
            
        if rrset_type == 'NAPTR':
            values = rrset_values[0]
            
            naptr_value = rrset_values[0]
            order = naptr_value.order
            pref = naptr_value.preference
            flag = naptr_value.flags
            params_naptr = naptr_value.service

            params += '&order={}&pref={}&flag={}&params={}'.format(order, pref, flag, params_naptr)
            if hasattr(naptr_value, 'replacement'):
                replace = naptr_value.replacement
                params += '&replace={}'.format(replace)
                
            if hasattr(naptr_value, 'regexp'):
                regexp = naptr_value.regexp
                params += '&regexp={}'.format(regexp)
                
        if rrset_type == 'TLSA':
            values = rrset_values[0].split()

            record = values[0]
            tlsa_usage = values[1]
            tlsa_selector = values[2]
            tlsa_matching_type = values[3]

            params += '&record={}&tlsa_usage={}&tlsa_selector={}&tlsa_matching_type={}'.format(record, tlsa_usage, tlsa_selector, tlsa_matching_type)
            
        return self._request('dns/add-record', params)
    
    def record_delete(self, domain_name, record_id):
        params = 'domain-name={}&record-id={}'.format(domain_name, record_id)
        return self._request('dns/delete-record', params)


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

    def __init__(self, id, auth_id, auth_password, *args, **kwargs):
        self.log = getLogger(f"ClouDNSProvider[{id}]")
        self.log.debug("__init__: id=%s, auth_id=***", id)
        super().__init__(id, *args, **kwargs)
        self._client = ClouDNSClient(auth_id, auth_password)

        self._zone_records = {}

    def _data_for_multiple(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [v["record"] + "." if v["type"] not in ["A", "AAAA", "TXT", "SPF"] else v["record"] for v in records],
        }



    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_TXT = _data_for_multiple
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
                self._zone_records[zone.name] = self._client.zone_records(zone.name[:-1])
            except ClouDNSClientNotFound:
                return []
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
        
        if 'status' in records_data and records_data['status'] == 'Failed':
            self.log.info("populate: no existing zone, trying to create it")
            response = self._client.zone_create(zone.name[:-1], 'master')
            if 'id' in response and response['id'] == 'not_found':
                e = ClouDNSClientUnknownDomainName(
                    'Missing domain name'
                )
                e.__cause__ = None
                raise e
            
            if (self.isGeoDNS(response['statusDescription'])):
                response = self._client.zone_create(zone.name[:-1], 'geodns')
            
            if(response['status'] == 'Failed'):
                e = ClouDNSClientUnknownDomainName(f"{response['status']} : {response['statusDescription']}")
                e.__cause__ = None
                raise e
            self.log.info("populate: zone has been successfully created")
            records_data = self._client.zone_records(zone.name[:-1])
            
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
        self.log.info(
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

    def _apply_update(self, change):
        self._apply_delete(change)
        self._apply_create(change)
        
    def records_are_same(self, existing):
        zone = existing.zone
        record_ids = []
        for record_id, record in self.zone_records(zone).items():
            for value in existing.values:
                if existing._type == 'NAPTR' and record['type'] == 'NAPTR':                    
                    if (
                        existing.name == record['host']
                        and value.order == int(record['order'])
                        and value.preference == int(record['pref'])
                        and value.flags == record['flag']
                    ):
                        record_ids.append(record_id)
                elif existing._type == 'SSHFP' and record['type'] == 'SSHFP':
                    if (
                        existing.name == record['host']
                        and value.fingerprint_type == int(record['fp_type'])
                        and value.algorithm == int(record['algorithm'])
                        and value.fingerprint == record['record']
                    ):
                        record_ids.append(record_id)
                elif existing._type == 'SRV' and record['type'] == 'SRV':
                    if (
                        existing.name == record['host']
                        and value.priority == int(record['priority'])
                        and value.weight == int(record['weight'])
                        and value.port == record['port']
                        and value.target == record['record']
                    ):
                        record_ids.append(record_id)
                elif existing._type == 'CAA' and record['type'] == 'CAA':
                    if (
                        existing.name == record['host']
                        and value.flags == record['caa_flag']
                        and value.tag == record['caa_type']
                        and value.value == record['caa_value']
                    ):
                        record_ids.append(record_id)
                elif existing._type == 'MX' and record['type'] == 'MX':
                    if (
                        existing.name == record['host']
                        and value.preference == int(record['priority'])
                        and value.exchange == record['record']
                    ):
                        record_ids.append(record_id)
                        
                elif existing._type == 'LOC' and record['type'] == 'LOC':
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
                        record_ids.append(record_id)
                else:
                    if (
                        existing.name == record['host']
                        and existing._type == record['type']
                        and value == record['record']
                    ):
                        record_ids.append(record_id)
        return record_ids


    def _apply_delete(self, change):
        existing = change.existing
        zone = existing.zone
        record_ids = self.records_are_same(existing)
        
        for record_id in record_ids:
            self._client.record_delete(zone.name[:-1], record_id)


    def _apply(self, plan):
        desired = plan.desired
        
        changes = plan.changes
        zone = desired.name[:-1]
        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        try:
            self._client.zone(zone)
        except ClouDNSClientNotFound:
            self.log.info("_apply: no existing zone, trying to create it")
            try:
                self._client.zone_create(zone, 'master')
                self.log.info("_apply: zone has been successfully created")
            except ClouDNSClientNotFound:
                e = ClouDNSClientUnknownDomainName(
                    "Domain " + zone + " is not "
                    "registered at ClouDNS. "
                    "Please register or "
                    "transfer it here "
                    "to be able to manage its "
                    "DNS zone."
                )
                e.__cause__ = None
                raise e

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f"_apply_{class_name.lower()}")(change)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
