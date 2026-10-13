"""The GTK 3 window: the checks grouped by level, and details for the selected check."""

from __future__ import annotations

import logging
import threading
from collections import Counter

import gi

# The GTK version must be chosen before importing from gi.repository.
gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk

from mojitoshield import privileged, scan
from mojitoshield.distribution import current_distribution
from mojitoshield.i18n import translate
from mojitoshield.results import CheckResult, Status
from mojitoshield.scan import CHECKS, CheckDefinition

LOGGER = logging.getLogger(__name__)

APPLICATION_ID = "org.mojitoshield.MojitoShield"
DEFAULT_WINDOW_SIZE = (900, 720)
# Below this width the list and the details are stacked instead of side by side.
NARROW_WINDOW_WIDTH = 720
LIST_WIDTH = 360
LIST_MIN_SIZE = (280, 220)
STACKED_LIST_SHARE = 0.48
DETAIL_MAX_WIDTH_CHARS = 72
PENDING_ICON = "content-loading-symbolic"
EXTENDED_SCAN_ICON = "dialog-password-symbolic"
STATUS_ICONS = {
    Status.OK: "emblem-default-symbolic",
    Status.WARNING: "dialog-warning-symbolic",
    Status.UNKNOWN: "dialog-question-symbolic",
    Status.AUTH_REQUIRED: "system-lock-screen-symbolic",
}


def status_presentation(result: CheckResult | None) -> tuple[str, str]:
    """Return the status text and icon name; None means the check has not finished yet."""
    if result is None:
        return translate("status.pending"), PENDING_ICON
    status = result.outcome.status
    return translate(f"status.{status.value}"), STATUS_ICONS[status]


def set_margins(widget: Gtk.Widget, *, top: int, bottom: int, start: int, end: int) -> None:
    widget.set_margin_top(top)
    widget.set_margin_bottom(bottom)
    widget.set_margin_start(start)
    widget.set_margin_end(end)


def wrapping_label(*, selectable: bool = False) -> Gtk.Label:
    """Return a start-aligned label that wraps, with lines short enough to read in wide windows."""
    label = Gtk.Label()
    label.set_xalign(0)
    label.set_halign(Gtk.Align.START)
    label.set_line_wrap(True)
    label.set_max_width_chars(DETAIL_MAX_WIDTH_CHARS)
    label.set_selectable(selectable)
    return label


def heading_label(text: str) -> Gtk.Label:
    label = Gtk.Label()
    label.set_markup(f"<b>{GLib.markup_escape_text(text)}</b>")
    label.set_xalign(0)
    return label


def confirm_unsupported_distribution() -> bool:
    """Return True on Mint or LMDE, and otherwise whether the user chooses to continue."""
    supported, distribution_name = current_distribution()
    if supported:
        return True

    dialog = Gtk.MessageDialog(
        transient_for=None,
        flags=Gtk.DialogFlags.MODAL,
        message_type=Gtk.MessageType.WARNING,
        buttons=Gtk.ButtonsType.NONE,
        text=translate("app.unsupported.title"),
    )
    dialog.format_secondary_text(
        translate(
            "app.unsupported.body",
            distribution=distribution_name or translate("app.unknown_distribution"),
        )
    )
    dialog.add_button(translate("app.abort"), Gtk.ResponseType.CANCEL)
    dialog.add_button(translate("app.continue"), Gtk.ResponseType.ACCEPT)
    response = dialog.run()
    dialog.destroy()
    return response == Gtk.ResponseType.ACCEPT


class CheckRow(Gtk.ListBoxRow):
    """One check in the list: its title and its status, or Checking… until the result arrives."""

    def __init__(self, definition: CheckDefinition) -> None:
        super().__init__()
        self.definition = definition
        self.title = translate(f"check.{definition.check_id}.title")

        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        set_margins(content, top=8, bottom=8, start=10, end=10)
        self.status_icon = Gtk.Image()
        content.pack_start(self.status_icon, False, False, 0)

        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        title_label = Gtk.Label(label=self.title)
        title_label.set_xalign(0)
        title_label.set_hexpand(True)
        title_label.set_line_wrap(True)
        labels.pack_start(title_label, False, False, 0)

        self.status_label = Gtk.Label()
        self.status_label.set_xalign(0)
        self.status_label.get_style_context().add_class("dim-label")
        labels.pack_start(self.status_label, False, False, 0)
        content.pack_start(labels, True, True, 0)
        self.add(content)
        self.show_result(None)

    def show_result(self, result: CheckResult | None) -> None:
        status_text, icon_name = status_presentation(result)
        self.status_label.set_text(status_text)
        self.status_icon.set_from_icon_name(icon_name, Gtk.IconSize.MENU)
        self.get_accessible().set_name(f"{self.title}: {status_text}")


class MojitoShieldWindow(Gtk.ApplicationWindow):
    def __init__(self, application: Gtk.Application) -> None:
        super().__init__(application=application)
        self.set_title(translate("app.title"))
        self.set_default_size(*DEFAULT_WINDOW_SIZE)

        self._rows: dict[str, CheckRow] = {}
        self._results: dict[str, CheckResult] = {}
        # Results of an older scan are ignored if the user started a new one meanwhile.
        self._scan_number = 0
        self._layout_orientation: Gtk.Orientation | None = None

        self._build_header()
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margins(outer, top=16, bottom=16, start=20, end=20)
        self.add(outer)

        outer.pack_start(self._build_summary(), False, False, 0)

        self.main_paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.main_paned.set_wide_handle(True)
        self.main_paned.set_vexpand(True)
        self.main_paned.connect("size-allocate", self._adapt_layout)
        outer.pack_start(self.main_paned, True, True, 0)
        # Extra width goes to the detail panel; the list keeps its width.
        self.main_paned.pack1(self._build_check_list(), False, False)
        self.main_paned.pack2(self._build_detail_panel(), True, False)

        self.show_all()
        first_row = self._rows[CHECKS[0].check_id]
        self.check_list.select_row(first_row)
        # Start keyboard focus in the check list, not in the selectable detail text.
        first_row.grab_focus()
        self._start_scan()

    def _build_header(self) -> None:
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title(translate("app.title"))
        self.set_titlebar(header)

        refresh_action = Gio.SimpleAction.new("refresh", None)
        refresh_action.connect("activate", lambda *_args: self._start_scan())
        self.add_action(refresh_action)
        self._refresh_action = refresh_action

        refresh_button = Gtk.Button.new_from_icon_name(
            "view-refresh-symbolic", Gtk.IconSize.BUTTON
        )
        refresh_button.set_tooltip_text(translate("app.refresh"))
        refresh_button.get_accessible().set_name(translate("app.refresh"))
        refresh_button.set_action_name("win.refresh")
        header.pack_end(refresh_button)

    def _build_summary(self) -> Gtk.Widget:
        """Build the summary line, with the Extended scan button for checks that need it."""
        summary = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.summary_label = Gtk.Label()
        self.summary_label.set_xalign(0)
        self.summary_label.set_line_wrap(True)
        summary.pack_start(self.summary_label, True, True, 0)

        self.extended_button = Gtk.Button(label=translate("app.extended_scan"))
        self.extended_button.set_image(
            Gtk.Image.new_from_icon_name(EXTENDED_SCAN_ICON, Gtk.IconSize.BUTTON)
        )
        self.extended_button.set_always_show_image(True)
        self.extended_button.set_valign(Gtk.Align.CENTER)
        # The theme's highlight colour, so the button stands out as the next step.
        self.extended_button.get_style_context().add_class("suggested-action")
        self.extended_button.connect("clicked", lambda _button: self._start_extended_scan())
        # Shown only when a check needs permission, so show_all() must not show it.
        self.extended_button.set_no_show_all(True)
        summary.pack_end(self.extended_button, False, False, 0)
        return summary

    def _build_check_list(self) -> Gtk.Widget:
        self.check_list = Gtk.ListBox()
        self.check_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.check_list.set_header_func(self._level_header)
        self.check_list.connect("row-selected", lambda _list, _row: self._show_selected_detail())
        self.check_list.get_accessible().set_name(translate("app.check_list"))
        for definition in sorted(CHECKS, key=lambda definition: definition.level):
            row = CheckRow(definition)
            self._rows[definition.check_id] = row
            self.check_list.add(row)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_size_request(*LIST_MIN_SIZE)
        scroller.add(self.check_list)
        return scroller

    def _build_detail_panel(self) -> Gtk.Widget:
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margins(detail_box, top=8, bottom=8, start=18, end=10)

        self.detail_title = wrapping_label()
        detail_box.pack_start(self.detail_title, False, False, 0)

        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.detail_status_icon = Gtk.Image()
        self.detail_status_label = Gtk.Label()
        self.detail_status_label.set_xalign(0)
        status_box.pack_start(self.detail_status_icon, False, False, 0)
        status_box.pack_start(self.detail_status_label, False, False, 0)
        detail_box.pack_start(status_box, False, False, 0)

        self.detail_result = wrapping_label(selectable=True)
        detail_box.pack_start(self.detail_result, False, False, 0)

        self.detail_heading = heading_label(translate("app.details"))
        detail_box.pack_start(self.detail_heading, False, False, 8)

        # Only the result text can be selected, so Tab stops in the details once.
        self.detail_explanation = wrapping_label()
        detail_box.pack_start(self.detail_explanation, False, False, 0)

        self.detail_evidence = wrapping_label()
        self.detail_evidence.set_no_show_all(True)
        detail_box.pack_start(self.detail_evidence, False, False, 0)

        footer = wrapping_label()
        footer.set_text(translate("app.footer"))
        footer.get_style_context().add_class("dim-label")
        detail_box.pack_end(footer, False, False, 8)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.add(detail_box)
        return scroller

    def _level_header(self, row: CheckRow, before: CheckRow | None) -> None:
        """Put a level heading above the first row of each level."""
        level = row.definition.level
        if before is not None and before.definition.level == level:
            row.set_header(None)
            return
        if row.get_header() is not None:
            return
        heading = heading_label(translate(f"level.{level}"))
        heading.set_margin_top(4 if before is None else 14)
        heading.set_margin_bottom(4)
        row.set_header(heading)

    def _adapt_layout(self, _widget, allocation) -> None:
        """Stack the list and the details in narrow windows; put them side by side in wide ones."""
        orientation = (
            Gtk.Orientation.VERTICAL
            if allocation.width < NARROW_WINDOW_WIDTH
            else Gtk.Orientation.HORIZONTAL
        )
        # Set the split on first layout and on orientation changes;
        # otherwise keep where the user dragged it.
        if orientation == self._layout_orientation:
            return
        self._layout_orientation = orientation
        self.main_paned.set_orientation(orientation)
        self.main_paned.set_position(
            int(allocation.height * STACKED_LIST_SHARE)
            if orientation == Gtk.Orientation.VERTICAL
            else LIST_WIDTH
        )

    def _show_selected_detail(self) -> None:
        row = self.check_list.get_selected_row()
        if row is None:
            self._show_detail_prompt()
        else:
            self._show_check_detail(row.definition)

    def _show_detail_prompt(self) -> None:
        self._set_detail_title(translate("app.title"))
        self.detail_status_label.set_text("")
        self.detail_status_icon.clear()
        self.detail_result.set_text(translate("app.select_check"))
        self.detail_heading.hide()
        self.detail_explanation.hide()
        self.detail_evidence.hide()

    def _show_check_detail(self, definition: CheckDefinition) -> None:
        result = self._results.get(definition.check_id)
        status_text, icon_name = status_presentation(result)
        self._set_detail_title(translate(f"check.{definition.check_id}.title"))
        self.detail_status_icon.set_from_icon_name(icon_name, Gtk.IconSize.MENU)
        self.detail_status_label.set_text(status_text)
        self.detail_heading.show()
        self.detail_explanation.set_text(translate(f"check.{definition.check_id}.description"))
        self.detail_explanation.show()

        if result is None:
            self.detail_result.set_text(translate("scan.pending"))
            self.detail_evidence.hide()
            return
        outcome = result.outcome
        self.detail_result.set_text(translate(outcome.message_id, **outcome.data))
        self.detail_evidence.set_text(translate("app.evidence", evidence=outcome.evidence))
        self.detail_evidence.set_visible(bool(outcome.evidence))

    def _set_detail_title(self, text: str) -> None:
        self.detail_title.set_markup(f"<big><b>{GLib.markup_escape_text(text)}</b></big>")

    def _show_results(self, results: tuple[CheckResult, ...]) -> None:
        for result in results:
            self._results[result.check_id] = result
            self._rows[result.check_id].show_result(result)
        self._show_selected_detail()

    def _checks_needing_permission(self) -> tuple[str, ...]:
        return tuple(
            check_id
            for check_id, result in self._results.items()
            if result.outcome.status is Status.AUTH_REQUIRED
        )

    def _start_scan(self) -> None:
        self._scan_number += 1
        scan_number = self._scan_number
        self._results.clear()
        for row in self._rows.values():
            row.show_result(None)
        self._show_selected_detail()
        self.extended_button.hide()
        self._refresh_action.set_enabled(False)
        self.summary_label.set_text(translate("app.scanning", count=str(len(CHECKS))))

        def run_in_background() -> None:
            try:
                results = scan.run_checks()
            except Exception as error:  # noqa: BLE001
                # Any error must still reach the window, or it would show Checking… forever.
                LOGGER.error("Security scan failed (%s).", type(error).__name__)
                results = ()
            GLib.idle_add(self._finish_scan, scan_number, results)

        threading.Thread(target=run_in_background, name="mojitoshield-scan", daemon=True).start()

    def _finish_scan(self, scan_number: int, results: tuple[CheckResult, ...]) -> bool:
        if scan_number != self._scan_number:
            return GLib.SOURCE_REMOVE

        self._show_results(results)
        if results:
            self._update_summary()
            self._update_extended_button()
        else:
            self.summary_label.set_text(translate("app.scan_failed"))
        self._refresh_action.set_enabled(True)
        return GLib.SOURCE_REMOVE

    def _update_summary(self, prefix: str = "") -> None:
        counts = Counter(result.outcome.status for result in self._results.values())
        summary_key = "app.summary_incomplete" if counts[Status.AUTH_REQUIRED] else "app.summary"
        summary = translate(
            summary_key,
            ok=str(counts[Status.OK]),
            warning=str(counts[Status.WARNING]),
            unknown=str(counts[Status.UNKNOWN]),
            auth=str(counts[Status.AUTH_REQUIRED]),
        )
        self.summary_label.set_text(f"{prefix} {summary}".strip())

    def _update_extended_button(self) -> None:
        if not self._checks_needing_permission():
            self.extended_button.hide()
            return

        available = privileged.privileged_helper_available()
        label_key = "app.extended_scan" if available else "app.extended_scan_missing"
        self.extended_button.set_label(translate(label_key))
        self.extended_button.set_sensitive(available)
        self.extended_button.set_tooltip_text(
            "" if available else translate("app.extended_scan_missing_tip")
        )
        self.extended_button.show()

    def _start_extended_scan(self) -> None:
        check_ids = self._checks_needing_permission()
        if not check_ids:
            return

        self._refresh_action.set_enabled(False)
        self.extended_button.set_sensitive(False)
        self.summary_label.set_text(translate("app.extended_scanning"))

        def run_in_background() -> None:
            try:
                results = privileged.run_privileged_checks(check_ids)
                problem_key = ""
            except privileged.PrivilegedScanCancelled:
                results = ()
                problem_key = "app.extended_cancelled"
            except privileged.PrivilegedScanError as error:
                LOGGER.warning("Extended scan failed (%s).", type(error).__name__)
                results = ()
                problem_key = "app.extended_failed"
            GLib.idle_add(self._finish_extended_scan, results, problem_key)

        threading.Thread(
            target=run_in_background, name="mojitoshield-extended-scan", daemon=True
        ).start()

    def _finish_extended_scan(self, results: tuple[CheckResult, ...], problem_key: str) -> bool:
        self._show_results(results)
        self._update_summary(translate(problem_key) if problem_key else "")
        self._update_extended_button()
        self._refresh_action.set_enabled(True)
        return GLib.SOURCE_REMOVE


class MojitoShieldApplication(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APPLICATION_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window: MojitoShieldWindow | None = None

    def do_startup(self) -> None:
        Gtk.Application.do_startup(self)
        Gtk.Window.set_default_icon_name(APPLICATION_ID)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_args: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])
        self.set_accels_for_action("win.refresh", ["F5", "<Control>r"])

    def do_activate(self) -> None:
        # Starting the app again while it runs brings the open window to the front.
        if self.window is not None:
            self.window.present()
            return
        if not confirm_unsupported_distribution():
            self.quit()
            return
        self.window = MojitoShieldWindow(self)


def main() -> int:
    logging.basicConfig(level=logging.WARNING)
    return MojitoShieldApplication().run(None)
