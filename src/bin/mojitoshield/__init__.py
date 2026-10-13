"""MojitoShield: local, read-only security checks for Linux Mint.

The package is split by responsibility:

- results: the status codes and result types every check returns
- system: running read-only commands and reading the clock
- distribution: recognising Linux Mint and LMDE
- checks: the nine checks, one module each (see docs/check-contracts.md)
- scan: the list of checks and running them all
- privileged: the optional Extended scan through PolicyKit
- i18n: the user-facing texts
- app: the GTK window

Everything except app and i18n is language-independent analysis code.
"""
