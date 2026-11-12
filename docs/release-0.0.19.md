# 0.0.19 preparation and validation

Status: **unreleased; blocked on the agreed #25 D7 guards and D8 review**.
Prepared on 2026-11-12. Do not tag or publish this branch in its current state.

## Source and scope

Base: v0.0.18, `869f7a4a6b049a2cb985fd86fdefd197538c0fc5`.

Backported with upstream commit references; original contributors are credited:

- `184aa605460e4ba37caaeffd2f41eb739dc98bd7`: escaped TXT removal, PR #32.
- `35a845af2de692c5064e5db9305a4f29eaf87904`: MX/SRV removal, PR #44.
- `5be407816a2a1cb896070c1cb3d65f1c5578d6cc`: constrain structured deletion
  matching to MX/SRV and preserve the NAPTR boundary, PR #44.

Both MX/SRV commits are required. No DS code, 0.1.0 dependency changes, or the
0.0.18-specific publication workflow/script are included. The package metadata
continues to require Python >=3.6, octoDNS >=0.9.17 and requests >=2.27.0.

Additional tests exercise MX/SRV plan/apply/read-back through a synthetic HTTP
API, retain unchanged rows, check desired-state immutability, and require an
empty second plan. New backported mock assertions use tuple indexing so they do
not require Python 3.8's call_args.args/kwargs properties.

## Local verification

All runs used `python -m pytest tests/ --disable-network -q`.

| Python | octoDNS | Passed | Skipped |
| --- | --- | --- | --- |
| 3.8.20 | 0.9.17 | 168 | 29 |
| 3.8.20 | 1.10.0 | 173 | 24 |
| 3.10.22 | 1.3.0 | 173 | 24 |
| 3.10.22 | 1.22.0 | 173 | 24 |
| 3.12.14 | 1.22.0 | 173 | 24 |

The Python 3.8 / octoDNS 0.9.17 run also passed with requests pinned to its
minimum 2.27.0. Skips are opt-in live/integration tests and record types missing
from older octoDNS versions. Python 3.6 was not executed; its metadata floor is
preserved, not newly certified by these runs.

Wheel and sdist built successfully with `python -m build`; `twine check` passed
for both. These are preparation artifacts, not approved release artifacts.
The dependency metadata and packaged provider are checked separately.

## Remaining release gates

1. Integrate istr's focused D7 patch and tests: zero-match deletes fail clearly;
   unsupported TLSA update/delete fail diagnostically, preserving the existing
   TLSA TTL-only path. No such patch was present in upstream PRs or the public
   branches inspected in istr's fork on the preparation date. This work has
   deliberately not been duplicated.
2. Verify D8: preserve inactive rows, including full-name/type deletion. The
   inherited legacy delete matcher does not filter inactive rows. Review the
   backported value-deletion paths under the same ownership boundary.
3. Repeat the matrix and packaging checks after those changes; inspect the
   complete diff against the base tag for accidental 0.1.0 additions.
4. Perform explicitly configured isolated-zone live checks, including read-back
   and an empty second plan. Local convergence tests above use synthetic data;
   no live DNS writes were made during preparation.
5. Approve the final commit and rebuild/verify its artifacts before creating the
   tag, GitHub release, or PyPI publication. Never use main's publication script
   unchanged: it is pinned to 0.0.18 and that release's hashes.

Successful backports do not add transactional rollback, fix other structured
record matchers, or support simultaneous TTL/value changes. Errors can still
follow partial writes in legacy paths. Review production plans: obsolete
TXT/MX/SRV rows previously left behind can now be deleted.
