=======
History
=======

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

0.2.2 (Unreleased)
------------------

This release marks a breaking change. Now the script "tags" recorded entries in
the security groups, e.g. ``[ip-liberator] SSH John`` instead of only ``SSH John``.
That helps to identify what IP Liberator added and what was added by hand.

By default, the tag is **ip-liberator**, but can be change through the new
option ``--tag``. If the user wants the previous behavior, i.e. without a tag,
he or she must pass the option ``--no-tag``.

Added
+++++

- Add option ``--operator`` to change the profile operator.
- Add short option ``-p`` for ``--profile``
- Add option ``--version`` to show current script version.

Changed
+++++++

- Add option ``--tag`` to identify entries added by the script.
- Migrate build system to Poetry

0.2.1 (2019-04-19)
------------------

- Fix documentation

0.2.0 (2019-04-19)
------------------

This release marks as the first to be published to PyPI.

No new functionality was added. The version was changed was to place a history mark.

- Added documentation.
- Added full coverage tests.
- Code refactoring.

0.1.1 (2018-10-16)
------------------

- Better console output.
- Added option ``--revoke-only``.
- Don't reauthorize if the IP address is already in the security group.
- Authorizing and revoking in batch to be more efficient.
- Bugfixes

0.1.0 (2018-09-27)
------------------

- Added option ``--my-ip`` to inform an IP address explicitly.
- Show in console the security groups being processed.
- Allow use as script by reading JSON as external config.
