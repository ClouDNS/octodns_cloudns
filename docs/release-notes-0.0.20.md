# octodns-cloudns 0.0.20

- Add DS record support in DNS hosting zones, including a compatibility model
  for octoDNS 0.9.17. Registrar DNSSEC settings are outside this provider's scope.
- Reconcile DS values by API record ID: preserve retained values and metadata,
  update changed values and TTLs, and remove obsolete or duplicate active rows.
  Preserve inactive DS records and reject unsupported GeoDNS DS rows.
- Create NS delegations before DS records, delete DS before NS, and retain an
  active delegation while replacing NS values. Reject missing-delegation plans
  before any writes. Include a complete NS + DS configuration example.
- Preserve Python >=3.6, octoDNS >=0.9.17 and requests >=2.27.0 dependency floors.
  Add standard Python 3.6.15 CI with octoDNS 0.9.17 and 0.9.21 and make DS model
  registration repeatable.
- Verify API errors, ambiguous writes, cache invalidation and plan convergence.
  Live checks on 1wpvsox.com confirmed combined NS/DS operations and cleanup.

### Upgrade notes

- DS records that were previously ignored now participate in synchronization.
  Review the plan before applying an existing configuration; include desired DS
  records and their same-owner NS delegation in the parent zone configuration.
- Inactive DS rows are preserved. Remove them manually before deleting their
  final NS delegation. Non-DS legacy limitations documented for 0.0.19 remain.
