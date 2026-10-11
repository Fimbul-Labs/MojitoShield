#!/usr/bin/env python3
"""GTK 3 desktop prototype for MojitoShield."""

from __future__ import annotations

import locale
import logging
import os
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk

from mojitoshield_core import (
    CHECKS,
    CheckResult,
    PrivilegedScanCancelled,
    PrivilegedScanError,
    Status,
    current_distribution,
    privileged_helper_available,
    run_privileged_checks,
)
from mojitoshield_i18n import language_from_locale, translate


LOGGER = logging.getLogger(__name__)


def configure_locale() -> str:
    """Follow the desktop locale and set direction for Arabic locales."""
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        LOGGER.warning("Could not apply the desktop locale.")

    language = language_from_locale()
    if language == "ar":
        Gtk.Widget.set_default_direction(Gtk.TextDirection.RTL)
    return language


def confirm_unsupported_distribution(language: str) -> bool:
    supported, distribution_name = current_distribution()
    if supported:
        return True

    if distribution_name is None:
        distribution_name = translate("app.unknown_distribution", language)
    dialog = Gtk.MessageDialog(
        transient_for=None,
        flags=Gtk.DialogFlags.MODAL,
        message_type=Gtk.MessageType.WARNING,
        buttons=Gtk.ButtonsType.NONE,
        text=translate("app.unsupported.title", language),
    )
    dialog.format_secondary_text(
        translate("app.unsupported.body", language, distribution=distribution_name)
    )
    dialog.add_button(translate("app.abort", language), Gtk.ResponseType.CANCEL)
    dialog.add_button(translate("app.continue", language), Gtk.ResponseType.ACCEPT)
    response = dialog.run()
    dialog.destroy()
    return response == Gtk.ResponseType.ACCEPT


class CheckRow(Gtk.ListBoxRow):
    _STATUS_ICONS = {
        Status.OK: "emblem-default-symbolic",
        Status.WARNING: "dialog-warning-symbolic",
        Status.UNKNOWN: "dialog-question-symbolic",
        Status.AUTH_REQUIRED: "system-lock-screen-symbolic",
    }

    def __init__(self, check: CheckResult, language: str) -> None:
        super().__init__()
        self.language = language
        self.check = check

        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        content.set_margin_top(8)
        content.set_margin_bottom(8)
        content.set_margin_start(10)
        content.set_margin_end(10)

        self.status_icon = Gtk.Image()
        content.pack_start(self.status_icon, False, False, 0)

        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self.title_label = Gtk.Label()
        self.title_label.set_xalign(0)
        self.title_label.set_hexpand(True)
        self.title_label.set_line_wrap(True)
        labels.pack_start(self.title_label, False, False, 0)

        self.status_label = Gtk.Label()
        self.status_label.set_xalign(0)
        self.status_label.get_style_context().add_class("dim-label")
        labels.pack_start(self.status_label, False, False, 0)
        content.pack_start(labels, True, True, 0)
        self.add(content)
        self.update(check)

    def update(self, check: CheckResult) -> None:
        self.check = check
        self.title_label.set_text(
            translate(f"check.{check.check_id}.title", self.language)
        )
        self.status_label.set_text(
            translate(f"status.{check.status.value}", self.language)
        )
        self.status_icon.set_from_icon_name(
            self._STATUS_ICONS[check.status], Gtk.IconSize.MENU
        )


def pending_result(check) -> CheckResult:
    return CheckResult(
        check_id=check.check_id,
        level=check.level,
        status=Status.UNKNOWN,
        message_id="scan.pending",
    )


class MojitoShieldWindow(Gtk.ApplicationWindow):
    def __init__(self, application: Gtk.Application, language: str) -> None:
        super().__init__(application=application)
        self.language = language
        self.set_title(translate("app.title", language))
        self.set_default_size(900, 720)
        self.set_border_width(0)

        self._rows: dict[str, CheckRow] = {}
        self._results: dict[str, CheckResult] = {}
        self._scan_number = 0
        self._selected_check_id: str | None = None

        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title(translate("app.title", language))
        self.set_titlebar(header)

        self.refresh_button = Gtk.Button.new_from_icon_name(
            "view-refresh-symbolic", Gtk.IconSize.BUTTON
        )
        self.refresh_button.set_tooltip_text(
            translate("app.refresh", language)
        )
        self.refresh_button.get_accessible().set_name(
            translate("app.refresh", language)
        )
        self.refresh_button.connect("clicked", self._start_scan)
        header.pack_end(self.refresh_button)

        self.extended_button = Gtk.Button(label=translate("app.extended_scan", language))
        self.extended_button.connect("clicked", self._start_extended_scan)
        self.extended_button.set_no_show_all(True)
        self.extended_button.hide()
        header.pack_end(self.extended_button)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_top(16)
        outer.set_margin_bottom(16)
        outer.set_margin_start(20)
        outer.set_margin_end(20)
        self.add(outer)

        self.summary_label = Gtk.Label()
        self.summary_label.set_xalign(0)
        self.summary_label.set_line_wrap(True)
        outer.pack_start(self.summary_label, False, False, 0)

        self.main_paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.main_paned.set_wide_handle(True)
        self.main_paned.set_vexpand(True)
        outer.pack_start(self.main_paned, True, True, 0)

        list_scroller = Gtk.ScrolledWindow()
        list_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_scroller.set_size_request(280, 220)
        self.main_paned.pack1(list_scroller, True, False)

        checks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        list_scroller.add(checks_box)
        self._list_boxes: list[Gtk.ListBox] = []
        for level in (1, 2):
            group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            heading_label = Gtk.Label()
            heading_label.set_markup(
                f"<b>{GLib.markup_escape_text(translate(f'level.{level}', language))}</b>"
            )
            heading_label.set_xalign(0)
            group.pack_start(heading_label, False, False, 4)

            list_box = Gtk.ListBox()
            list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
            list_box.connect("row-selected", self._on_row_selected)
            self._list_boxes.append(list_box)
            group.pack_start(list_box, False, False, 0)
            for definition in CHECKS:
                if definition.level != level:
                    continue
                row = CheckRow(pending_result(definition), language)
                self._rows[definition.check_id] = row
                list_box.add(row)
            checks_box.pack_start(group, False, False, 0)

        detail_scroller = Gtk.ScrolledWindow()
        detail_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_box.set_margin_top(8)
        detail_box.set_margin_bottom(8)
        detail_box.set_margin_start(18)
        detail_box.set_margin_end(10)
        detail_scroller.add(detail_box)
        self.main_paned.pack2(detail_scroller, True, False)

        self.detail_title = Gtk.Label()
        self.detail_title.set_xalign(0)
        self.detail_title.set_line_wrap(True)
        self.detail_title.get_style_context().add_class("title-3")
        detail_box.pack_start(self.detail_title, False, False, 0)

        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.detail_status_icon = Gtk.Image()
        self.detail_status_label = Gtk.Label()
        self.detail_status_label.set_xalign(0)
        status_box.pack_start(self.detail_status_icon, False, False, 0)
        status_box.pack_start(self.detail_status_label, False, False, 0)
        detail_box.pack_start(status_box, False, False, 0)

        self.detail_result = Gtk.Label()
        self.detail_result.set_xalign(0)
        self.detail_result.set_line_wrap(True)
        self.detail_result.set_selectable(True)
        detail_box.pack_start(self.detail_result, False, False, 0)

        self.detail_heading = Gtk.Label()
        self.detail_heading.set_markup(
            f"<b>{GLib.markup_escape_text(translate('app.details', language))}</b>"
        )
        self.detail_heading.set_xalign(0)
        detail_box.pack_start(self.detail_heading, False, False, 8)

        self.detail_explanation = Gtk.Label()
        self.detail_explanation.set_xalign(0)
        self.detail_explanation.set_line_wrap(True)
        self.detail_explanation.set_selectable(True)
        detail_box.pack_start(self.detail_explanation, False, False, 0)

        self.detail_evidence = Gtk.Label()
        self.detail_evidence.set_xalign(0)
        self.detail_evidence.set_line_wrap(True)
        self.detail_evidence.set_selectable(True)
        detail_box.pack_start(self.detail_evidence, False, False, 0)

        self.detail_footer = Gtk.Label(label=translate("app.footer", language))
        self.detail_footer.set_xalign(0)
        self.detail_footer.set_line_wrap(True)
        self.detail_footer.get_style_context().add_class("dim-label")
        detail_box.pack_end(self.detail_footer, False, False, 8)

        self.main_paned.connect("size-allocate", self._adapt_layout)
        self._show_detail_prompt()
        first_row = self._rows[CHECKS[0].check_id]
        first_list = first_row.get_parent()
        first_list.select_row(first_row)

        self.show_all()
        self.extended_button.hide()
        self._start_scan()

    def _adapt_layout(self, _widget, allocation) -> None:
        orientation = (
            Gtk.Orientation.VERTICAL
            if allocation.width < 720
            else Gtk.Orientation.HORIZONTAL
        )
        if self.main_paned.get_orientation() != orientation:
            self.main_paned.set_orientation(orientation)
            self.main_paned.set_position(
                int(allocation.height * 0.48)
                if orientation == Gtk.Orientation.VERTICAL
                else 360
            )

    def _show_detail_prompt(self) -> None:
        self.detail_title.set_text(translate("app.title", self.language))
        self.detail_status_label.set_text("")
        self.detail_status_icon.clear()
        self.detail_result.set_text(translate("app.select_check", self.language))
        self.detail_heading.hide()
        self.detail_explanation.hide()
        self.detail_evidence.hide()

    def _on_row_selected(self, _list_box, row) -> None:
        if row is None:
            return
        check_id = row.check.check_id
        if check_id == self._selected_check_id:
            return
        self._selected_check_id = check_id
        self._show_check_detail(self._results.get(check_id) or pending_result(row.check))

    def _show_check_detail(self, check: CheckResult) -> None:
        self.detail_title.set_text(
            translate(f"check.{check.check_id}.title", self.language)
        )
        self.detail_status_icon.set_from_icon_name(
            CheckRow._STATUS_ICONS[check.status], Gtk.IconSize.MENU
        )
        self.detail_status_label.set_text(
            translate(f"status.{check.status.value}", self.language)
        )
        self.detail_result.set_text(
            translate(check.message_id, self.language, **dict(check.data))
        )
        self.detail_heading.show()
        self.detail_explanation.set_text(
            translate(f"check.{check.check_id}.description", self.language)
        )
        self.detail_explanation.show()
        if check.evidence:
            self.detail_evidence.set_text(
                translate("app.evidence", self.language, evidence=check.evidence)
            )
            self.detail_evidence.show()
        else:
            self.detail_evidence.hide()

    def _start_scan(self, _button=None) -> None:
        self._scan_number += 1
        scan_number = self._scan_number
        self._results.clear()
        self.extended_button.hide()
        self.extended_button.set_sensitive(False)
        for definition in CHECKS:
            self._rows[definition.check_id].update(pending_result(definition))
        self._show_detail_prompt()

        self.refresh_button.set_sensitive(False)
        self.summary_label.set_text(
            translate("app.scanning", self.language, count=str(len(CHECKS)))
        )

        def scan() -> None:
            try:
                from mojitoshield_core import run_checks

                results = run_checks()
            except Exception as error:
                LOGGER.error("Security scan failed (%s).", type(error).__name__)
                results = ()
            GLib.idle_add(self._finish_scan, scan_number, results)

        threading.Thread(target=scan, name="mojitoshield-scan", daemon=True).start()

    def _finish_scan(self, scan_number: int, results: tuple[CheckResult, ...]) -> bool:
        if scan_number != self._scan_number:
            return GLib.SOURCE_REMOVE

        self._results = {result.check_id: result for result in results}
        for result in results:
            self._rows[result.check_id].update(result)
        selected = self._selected_check_id
        if selected is not None and selected in self._results:
            self._show_check_detail(self._results[selected])

        if results:
            self._update_summary()
            self._update_extended_button()
        else:
            self.summary_label.set_text(translate("app.scan_failed", self.language))
            self.extended_button.hide()

        self.refresh_button.set_sensitive(True)
        return GLib.SOURCE_REMOVE

    def _update_summary(self, prefix: str = "") -> None:
        counts = {status: 0 for status in Status}
        for result in self._results.values():
            counts[result.status] += 1
        summary = translate(
            "app.summary",
            self.language,
            ok=str(counts[Status.OK]),
            warning=str(counts[Status.WARNING]),
            unknown=str(counts[Status.UNKNOWN]),
            auth=str(counts[Status.AUTH_REQUIRED]),
        )
        self.summary_label.set_text(f"{prefix} {summary}".strip())

    def _update_extended_button(self) -> None:
        required = any(
            result.status is Status.AUTH_REQUIRED for result in self._results.values()
        )
        if not required:
            self.extended_button.hide()
            return

        available = privileged_helper_available()
        label_key = "app.extended_scan" if available else "app.extended_scan_missing"
        self.extended_button.set_label(translate(label_key, self.language))
        self.extended_button.set_sensitive(available)
        self.extended_button.set_tooltip_text(
            "" if available else translate("app.extended_scan_missing_tip", self.language)
        )
        self.extended_button.show()

    def _start_extended_scan(self, _button=None) -> None:
        check_ids = tuple(
            check_id
            for check_id, result in self._results.items()
            if result.status is Status.AUTH_REQUIRED
        )
        if not check_ids:
            return

        self.refresh_button.set_sensitive(False)
        self.extended_button.set_sensitive(False)
        self.summary_label.set_text(translate("app.extended_scanning", self.language))

        def scan() -> None:
            try:
                results = run_privileged_checks(check_ids)
                outcome = "success"
            except PrivilegedScanCancelled:
                results = ()
                outcome = "cancelled"
            except PrivilegedScanError as error:
                LOGGER.warning("Extended scan failed (%s).", type(error).__name__)
                results = ()
                outcome = "failed"
            GLib.idle_add(self._finish_extended_scan, results, outcome)

        threading.Thread(target=scan, name="mojitoshield-extended-scan", daemon=True).start()

    def _finish_extended_scan(self, results, outcome: str) -> bool:
        for result in results:
            self._results[result.check_id] = result
            self._rows[result.check_id].update(result)
        selected = self._selected_check_id
        if selected is not None and selected in self._results:
            self._show_check_detail(self._results[selected])

        message_key = {
            "cancelled": "app.extended_cancelled",
            "failed": "app.extended_failed",
        }.get(outcome, "")
        self._update_summary(
            translate(message_key, self.language) if message_key else ""
        )
        self._update_extended_button()
        self.refresh_button.set_sensitive(True)
        return GLib.SOURCE_REMOVE

class MojitoShieldApplication(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(
            application_id="org.mojitoshield.application",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.window = None
        self._distribution_confirmed = False
        self.language = "en"

    def do_activate(self) -> None:
        if self.window is not None:
            self.window.present()
            return
        if not self._distribution_confirmed:
            if not confirm_unsupported_distribution(self.language):
                self.quit()
                return
            self._distribution_confirmed = True

        self.window = MojitoShieldWindow(self, self.language)
        self.window.show_all()


def main() -> int:
    language = configure_locale()
    application = MojitoShieldApplication()
    application.language = language
    return application.run(None)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    raise SystemExit(main())