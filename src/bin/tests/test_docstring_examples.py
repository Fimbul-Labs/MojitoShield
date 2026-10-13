"""Run the Examples in the docstrings, so they stay true as the code changes."""

import doctest
import importlib
import pkgutil

import mojitoshield

# The window needs GTK and has no examples; importing __main__ would start the app.
SKIPPED_MODULES = {"mojitoshield.app", "mojitoshield.__main__"}


def load_tests(loader, tests, pattern):
    for module_info in pkgutil.walk_packages(mojitoshield.__path__, "mojitoshield."):
        if module_info.name in SKIPPED_MODULES:
            continue
        module = importlib.import_module(module_info.name)
        tests.addTests(doctest.DocTestSuite(module))
    return tests
