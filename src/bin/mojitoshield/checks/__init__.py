"""The nine read-only checks, one module each.

Every module has a `check()` function that returns an Outcome, and follows its
contract in docs/check-contracts.md. The order and levels are set in scan.py.

A check never raises. It catches the errors it expects, such as an unreadable
file, and reports Could not determine instead, so one check cannot stop the
others. scan.run_check() is the safety net for anything unexpected.
"""
