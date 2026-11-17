## ClouDNS API provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets ClouDNS.

### Installation

#### Command line

```
pip install octodns-cloudns
```

### Configuration

For more safety, we recommend you to use an API sub-user with limited permissions.
You can create it from [your ClouDNS account](https://www.cloudns.net/api-settings/)
and store your credentials in environment variables:

```bash
export CLOUDNS_API_AUTH_ID=XXXXX
export CLOUDNS_API_AUTH_PASSWORD=XXXXX
```

Then add your ClouDNS account to your octoDNS configuration file:

```yaml
providers:
  cloudns_account:
    class: octodns_cloudns.ClouDNSProvider
    auth_id: env/CLOUDNS_API_AUTH_ID
    auth_password: env/CLOUDNS_API_AUTH_PASSWORD
    # "sub_auth" must be enabled if *only* you log in using a sub-user.
    sub_auth: true
```


### Support Information

#### GeoDNS records

ClouDNSProvider suports GeoDNS records

#### Records

ClouDNSProvider suports А, AAAA, ALIAS, CAA, CNAME, DNAME, DS, MX, NS, PTR, SPF, SRV, SSHFP, TXT, TLSA, LOC and NAPTR

#### DS records and delegations

DS records are managed in the parent DNS hosting zone, not through registrar
DNSSEC settings. ClouDNS requires an active NS delegation at the same owner name:
for example, `child.example.com.` needs both NS and DS records in `example.com.`.
The zone's apex NS records do not satisfy a child delegation.

See [the complete NS + DS zone example](docs/ds-example.yaml). Replace the example
name servers and digests with those of the actual child zone.

NS and DS may be created or removed in one plan. The provider creates the NS
records before DS, removes DS before the delegation, and adds replacement NS
values before deleting old ones. Missing delegations and removal of the last
active NS while DS records remain are rejected before any plan writes. Inactive
DS records are preserved; remove those manually before removing their delegation.

#### Dynamic

ClouDNSProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
