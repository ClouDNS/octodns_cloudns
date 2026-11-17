# Release 0.0.20 validation

The DS implementation and delegation ordering were validated at commit
acc36c998523e8d8599931ad5bf84be63cb1d02a (PR #45).

All seven CI configurations passed: Python 3.6.15 with octoDNS 0.9.17 and
0.9.21; Python 3.8 with 0.9.17 and 1.10.0; Python 3.10 with 1.3.0 and
1.22.0; Python 3.12 with 1.22.0. Standard Python 3.6.15 containers reported
260 passed / 43 skipped with 0.9.17 and 268 passed / 35 skipped with 0.9.21.
Live delegation tests on 1wpvsox.com covered combined NS+DS creation, NS
replacement retaining DS, combined deletion and missing-delegation rejection
before writes. All four original rows were unchanged and temporary rows removed.

Publication builds wheel and sdist once, verifies all provider module bytes,
version and dependency metadata, checks installation and tests from the wheel,
and publishes the same SHA-256 verified bytes to GitHub and PyPI. Published
artifacts are reused on retry; conflicting tags or hashes abort publication.
