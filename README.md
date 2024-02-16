## ClouDNS API provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets ClouDNS.

### Installation

#### Command line

```
pip install octodns-cloudns
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-cloudns==0.0.1
```

### Configuration

```yaml
providers:
  cloudns_account:
    class: octodns.provider.cloudns.ClouDNSProvider
    auth_id: <api_auth_id>
    auth_password: <api_auth_password>
```

### Support Information

#### GeoDNS records

ClouDNSProvider suports GeoDNS records

#### Records

ClouDNSProvider suports AAAA, ALIAS, CAA, CNAME, DNAME, MX, NS, PTR, SPF, SRV, SSHFP, TXT, TLSA, LOC and NAPTR

#### Dynamic

ClouDNSProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
