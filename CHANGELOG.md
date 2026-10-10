# Changelog

## 0.0.18 — Unreleased

- Apply TTL-only changes with `dns/mod-record` for every API row of the managed
  name/type, including structured record types. Preserve IDs and raw value fields;
  do not delete or recreate rows for a TTL-only change.
- Validate TTL-only operations before any plan writes, fail on zero operations,
  and clear cached records after successful or failed applies.
- Avoid mutating desired records during legacy value updates. CNAME, ALIAS and
  DNAME value updates use `mod-record` instead of crashing on a missing `values`.
- Send form-encoded POST requests with bounded timeouts. Remove credential-bearing
  URL logging, the unused Bearer header, response-body logging and import-time
  logging configuration. Do not retry ambiguous writes automatically.
- Propagate API read errors except the explicit missing-domain response. Treat
  an empty list as an existing empty zone.
- Remove the exposed credential example and fixed account/domain defaults from
  integration tests. Integration requires explicit opt-in and environment values;
  CI unit tests have network access disabled.
- Keep the existing Python and octoDNS dependency floors. The floor bump belongs
  to 0.1.0.

### Known limits and release gates

- A change affecting both TTL and values is rejected before plan writes. Apply
  value changes and TTL changes in separate runs until 0.1.0.
- Rows with notes, failover, inactive status or GeoDNS location are rejected by
  the new modification path. This avoids assuming undocumented preservation of
  those settings. GeoDNS is not repaired by this release.
- The legacy multi-value update/delete path still has known matching and removal
  defects, notably CAA/LOC/TLSA and structured values; these remain tracked in #25.
  An explicit failure does not make that legacy path fully convergent.
- Existing per-client rate limiting remains unchanged; shared-IP limiting belongs
  to 0.1.0. There is no transactional rollback after a partial API failure.
- Before publication: run the gated live TTL read-back test and verify SSHFP/LOC
  write-field names against a dedicated paid test zone. Fixtures in unit tests
  model the API contract; they are not claimed to be captured live responses.
- Removing a public credential does not revoke it. Confirm rotation/revocation
  with its owner separately (issue #23).
