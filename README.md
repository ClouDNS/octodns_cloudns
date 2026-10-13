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

#### DS records (0.1.0)

DS supports multiple structured values, ID-preserving updates and TTL changes.
Requires Python >=3.10 and octoDNS >=1.22.0. See [DS documentation and YAML
example](docs/ds.md). This manages DS in hosted zones; signing and registrar
DNSSEC are outside its scope. This development branch is `0.1.0.dev0`, not a
0.0.19 patch release.

#### Dynamic

ClouDNSProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
