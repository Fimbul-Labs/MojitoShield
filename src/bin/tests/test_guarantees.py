"""Static checks for the product guarantees in the README."""

import ast
import re
import unittest
from pathlib import Path

from mojitoshield_core import CHECKS, SCREEN_LOCK_SETTINGS, Status
from mojitoshield_i18n import ENGLISH

SOURCE_ROOT = Path(__file__).parents[1]
ANALYSIS_SOURCES = ("mojitoshield_core.py", "mojitoshield_privileged.py")
ALL_SOURCES = (*ANALYSIS_SOURCES, "mojitoshield.py", "mojitoshield_i18n.py")
SYSTEMD_UNIT_SUFFIXES = (".service", ".socket", ".timer")
MESSAGE_PREFIXES = (
    "firewall",
    "updates",
    "screen_lock",
    "auto_login",
    "timeshift",
    "network_services",
    "apparmor",
    "disk_encryption",
    "boot_menu",
    "check",
)


def source(name: str) -> str:
    return (SOURCE_ROOT / name).read_text(encoding="utf-8")


def string_constants(name: str) -> set[str]:
    return {
        node.value
        for node in ast.walk(ast.parse(source(name)))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


class TranslationCatalogTests(unittest.TestCase):
    def analysis_message_ids(self) -> set[str]:
        pattern = re.compile(rf"^({'|'.join(MESSAGE_PREFIXES)})\.[a-z_]+$")
        return {
            value
            for name in ANALYSIS_SOURCES
            for value in string_constants(name)
            if pattern.match(value) and not value.endswith(SYSTEMD_UNIT_SUFFIXES)
        }

    def interface_message_ids(self) -> set[str]:
        message_ids = {
            node.args[0].value
            for node in ast.walk(ast.parse(source("mojitoshield.py")))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "translate"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        }
        # Keys chosen through variables, minus GTK action names that share the prefix.
        message_ids |= {
            value
            for value in string_constants("mojitoshield.py")
            if re.match(r"^app\.[a-z_.]+$", value)
        } - {"app.quit"}
        # Keys built at runtime from levels, statuses and the pending marker.
        message_ids |= {"level.1", "level.2", "scan.pending"}
        message_ids |= {f"status.{status.value}" for status in Status}
        return message_ids

    def test_every_result_message_has_catalog_text(self):
        message_ids = self.analysis_message_ids()
        self.assertGreater(len(message_ids), 40)
        for message_id in sorted(message_ids):
            with self.subTest(message_id=message_id):
                self.assertTrue(message_id in ENGLISH, message_id)

    def test_every_interface_message_has_catalog_text(self):
        for message_id in sorted(self.interface_message_ids()):
            with self.subTest(message_id=message_id):
                self.assertTrue(message_id in ENGLISH, message_id)

    def test_every_check_has_title_and_description(self):
        for definition in CHECKS:
            for part in ("title", "description"):
                key = f"check.{definition.check_id}.{part}"
                with self.subTest(key=key):
                    self.assertTrue(key in ENGLISH, key)

    def test_catalog_has_no_unused_result_messages(self):
        used = self.analysis_message_ids() | self.interface_message_ids()
        used |= {
            f"check.{definition.check_id}.{part}"
            for definition in CHECKS
            for part in ("title", "description")
        }
        self.assertEqual(sorted(set(ENGLISH) - used), [])


class OfflineAndReadOnlyTests(unittest.TestCase):
    NETWORK_MODULES = {
        "socket",
        "ssl",
        "http",
        "urllib",
        "ftplib",
        "smtplib",
        "requests",
        "asyncio",
        "xmlrpc",
        "telnetlib",
        "poplib",
        "imaplib",
    }
    WRITING_METHODS = {
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "mkdir",
        "rename",
        "replace",
        "chmod",
        "chown",
        "touch",
        "symlink_to",
        "hardlink_to",
        "remove",
        "removedirs",
        "makedirs",
        "rmtree",
        "copy",
        "copyfile",
        "move",
    }

    def test_no_network_modules_are_imported(self):
        for name in ALL_SOURCES:
            for node in ast.walk(ast.parse(source(name))):
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                else:
                    continue
                for module in modules:
                    with self.subTest(source=name, module=module):
                        self.assertNotIn(module.split(".")[0], self.NETWORK_MODULES)

    def test_analysis_code_does_not_write_files(self):
        for name in ANALYSIS_SOURCES:
            for node in ast.walk(ast.parse(source(name))):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                if isinstance(function, ast.Attribute):
                    with self.subTest(source=name, call=function.attr, line=node.lineno):
                        self.assertNotIn(function.attr, self.WRITING_METHODS)
                if isinstance(function, ast.Name) and function.id == "open":
                    with self.subTest(source=name, line=node.lineno):
                        self.fail("analysis code should use read-only Path helpers")

    def test_only_allowlisted_read_only_commands_are_run(self):
        allowed = {
            ("ufw", "status"),
            ("systemctl", "is-active"),
            ("systemctl", "is-enabled"),
            ("gsettings", "get"),
            ("findmnt", None),
            ("lsblk", None),
            ("xfconf-query", None),
            ("ip", "-json"),
        }
        commands = [
            query
            for settings in SCREEN_LOCK_SETTINGS.values()
            for query in (
                settings.lock_query,
                settings.idle_delay_query,
                settings.idle_enabled_query,
            )
            if query is not None
        ]
        for node in ast.walk(ast.parse(source("mojitoshield_core.py"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_run_command"
                and node.args
                and isinstance(node.args[0], ast.List)
            ):
                commands.append(
                    [
                        element.value if isinstance(element, ast.Constant) else None
                        for element in node.args[0].elts
                    ]
                )

        self.assertGreaterEqual(len(commands), 8)
        for arguments in commands:
            executable = arguments[0]
            subcommand = arguments[1] if len(arguments) > 1 else None
            with self.subTest(arguments=arguments):
                self.assertTrue(
                    (executable, subcommand) in allowed or (executable, None) in allowed
                )
                self.assertFalse({"--set", "-s", "set", "reset", "--create"} & set(arguments))


if __name__ == "__main__":
    unittest.main()
