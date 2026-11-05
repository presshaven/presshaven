"""Selective upload: rsync dry-run parsing, argv builders, and the button."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import project_upload as pu


class ArgvTests(unittest.TestCase):
    def test_changes_argv_is_a_dry_run_with_itemize(self):
        argv = pu.build_changes_argv("/l", _cfg())
        self.assertIn("-azn", argv)
        self.assertIn("--itemize-changes", argv)
        self.assertNotIn("--info=progress2", argv)

    def test_selective_argv_restricts_to_file_list(self):
        argv = pu.build_selective_rsync_argv("/l", _cfg(), "/tmp/f")
        self.assertIn("--files-from=/tmp/f", argv)
        self.assertTrue(argv[-1].endswith("/"))
        self.assertNotIn("-n", argv)
        self.assertNotIn("-azn", argv)


class ParseTests(unittest.TestCase):
    def test_only_files_sent_are_listed(self):
        out = "\n".join([
            "<f.st...... docker-compose.yml",
            ".d..t...... images/",
            "<f+++++++++ images/a b.py",
            "cL+++++++++ link",
            "*deleting   old.txt",
            "sent 1 bytes  received 2 bytes",
        ])
        self.assertEqual(pu.parse_changed_files(out),
                         ["docker-compose.yml", "images/a b.py", "link"])

    def test_empty_output(self):
        self.assertEqual(pu.parse_changed_files(""), [])


def _cfg():
    from core.state import RemoteConfig
    return RemoteConfig(host="h", user="u", key_path="/k", remote_path="/p")


class ButtonTests(unittest.TestCase):
    def test_button_sits_right_after_full_upload_button(self):
        from PyQt6.QtWidgets import QApplication, QHBoxLayout
        from ui.remote_config_widget import RemoteConfigWidget
        QApplication.instance() or QApplication([])
        w = RemoteConfigWidget("edge", _cfg())
        self.assertEqual(w.selective_btn.text(), "Selective upload…")
        self.assertFalse(w.selective_btn.isEnabled())
        for lay in w.findChildren(QHBoxLayout):
            idx = lay.indexOf(w.sync_btn)
            if idx >= 0:
                self.assertEqual(lay.indexOf(w.selective_btn), idx + 1)
                return
        self.fail("sync row not found")


if __name__ == "__main__":
    unittest.main()
