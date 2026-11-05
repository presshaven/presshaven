"""LogPanel must not render a flood of output in one go (UI freeze)."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from ui import process_runner as pr

_app = QApplication.instance() or QApplication([])


class ThrottleTests(unittest.TestCase):
    def test_flood_is_rendered_in_bounded_slices(self):
        p = pr.LogPanel()
        p._enqueue("x\n" * (pr._RENDER_SLICE_CHARS * 3))
        p._render_slice()
        shown = p.text.toPlainText()
        self.assertLessEqual(len(shown), pr._RENDER_SLICE_CHARS + 1)
        self.assertTrue(p._backlog)
        self.assertTrue(p._render_timer.isActive())

    def test_backlog_is_capped_and_noted(self):
        p = pr.LogPanel()
        p._enqueue("y" * (pr._BACKLOG_MAX_CHARS * 2))
        self.assertLessEqual(len(p._backlog), pr._BACKLOG_MAX_CHARS)
        p._render_slice()
        self.assertIn("skipped", p.text.toPlainText())

    def test_exit_banner_comes_after_all_output(self):
        p = pr.LogPanel()
        p._enqueue("line1\nline2\n")
        p._suppress_finish = False
        p._on_finished(0, None)
        p._render_slice()
        text = p.text.toPlainText()
        self.assertLess(text.index("line2"), text.index("process exited"))
        self.assertEqual(p._backlog, "")


if __name__ == "__main__":
    unittest.main()
