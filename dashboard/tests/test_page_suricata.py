"""The Network IDS (Suricata) page's Alerts table supports multi-row selection
so a subset of alerts can be copied (Ctrl+C), not only the whole shown list.
"""
import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from PyQt6.QtCore import QItemSelectionModel  # noqa: E402
from PyQt6.QtGui import QGuiApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication, QTableWidget  # noqa: E402

from core import suricata_ctl  # noqa: E402
from core.state import AppState  # noqa: E402
from ui.page_suricata import SuricataPage  # noqa: E402

_app = QApplication.instance() or QApplication([])


def _alert(i: int, sev: int):
    return suricata_ctl.SuricataAlert(
        timestamp=f"2026-11-02T08:5{i}:00", src_ip="172.20.0.6", src_port=1000 + i,
        dest_ip="172.20.0.2", dest_port=80, signature=f"Sig {i}", sid=1000000 + i,
        category="Web", severity=sev, action="allowed", url=f"/path/{i}", user_agent="x")


class SuricataAlertSelectionTests(unittest.TestCase):
    def setUp(self):
        self.page = SuricataPage(AppState())
        self.page._alerts = [_alert(i, 1 if i % 2 else 3) for i in range(5)]
        self.page._ip_names = {}
        self.page._render_alerts()

    def _select_rows(self, *rows):
        self.page.alert_table.clearSelection()
        model = self.page.alert_table.model()
        flags = (QItemSelectionModel.SelectionFlag.Select
                 | QItemSelectionModel.SelectionFlag.Rows)
        for r in rows:
            self.page.alert_table.selectionModel().select(model.index(r, 0), flags)

    def test_table_allows_multi_row_selection(self):
        self.assertEqual(self.page.alert_table.selectionMode(),
                         QTableWidget.SelectionMode.ExtendedSelection)
        self.assertEqual(self.page.alert_table.selectionBehavior(),
                         QTableWidget.SelectionBehavior.SelectRows)

    def test_selected_alerts_are_returned_top_to_bottom(self):
        self._select_rows(3, 1)  # selected out of order
        shown = self.page._shown_alerts
        self.assertEqual(self.page._selected_alerts(), [shown[1], shown[3]])

    def test_copy_selected_copies_only_the_selection(self):
        self._select_rows(1, 3)
        self.page._copy_selected()
        lines = QGuiApplication.clipboard().text().splitlines()
        self.assertEqual(len(lines), 3)  # 1 header + 2 selected rows
        self.assertIn("selected alert(s) copied", self.page.status.text())
        self.assertTrue(self.page.status.text().startswith("2 "))

    def test_copy_selected_falls_back_to_all_shown_when_nothing_selected(self):
        self.page.alert_table.clearSelection()
        self.page._copy_selected()
        lines = QGuiApplication.clipboard().text().splitlines()
        self.assertEqual(len(lines), 6)  # 1 header + 5 shown rows
        self.assertNotIn("selected", self.page.status.text())

    def test_alerts_as_text_accepts_a_subset(self):
        subset = self.page._shown_alerts[:2]
        text = self.page._alerts_as_text(subset)
        self.assertEqual(len(text.splitlines()), 3)  # header + 2
        # Default (no arg) still covers everything shown.
        self.assertEqual(len(self.page._alerts_as_text().splitlines()), 6)


if __name__ == "__main__":
    unittest.main()
