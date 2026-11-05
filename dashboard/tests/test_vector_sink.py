"""Per-remote separate Vector sink: config round-trip and .env override."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.env_upload import apply_sink_override
from core.state import RemoteConfig, parse_remotes
from dataclasses import asdict

ENV = "# c\nFOO=1\nVECTOR_HOST=old.example\nVECTOR_PORT=6000\n"


class OverrideTests(unittest.TestCase):
    def test_no_sink_leaves_text_untouched(self):
        self.assertEqual(apply_sink_override(ENV, "edge", RemoteConfig()), ENV)

    def test_sink_host_and_port_replace_values_only(self):
        out = apply_sink_override(ENV, "edge", RemoteConfig(sink_host="10.1.2.3", sink_port=7000))
        self.assertIn("VECTOR_HOST=10.1.2.3", out)
        self.assertIn("VECTOR_PORT=7000", out)
        self.assertIn("FOO=1", out)
        self.assertIn("# c", out)

    def test_port_zero_keeps_env_port(self):
        out = apply_sink_override(ENV, "edge", RemoteConfig(sink_host="s"))
        self.assertIn("VECTOR_HOST=s", out)
        self.assertIn("VECTOR_PORT=6000", out)

    def test_missing_keys_are_added(self):
        out = apply_sink_override("FOO=1\n", "edge", RemoteConfig(sink_host="s", sink_port=1))
        self.assertIn("VECTOR_HOST=s", out)
        self.assertIn("VECTOR_PORT=1", out)

    def test_siem_project_never_overridden(self):
        self.assertEqual(apply_sink_override(ENV, "siem", RemoteConfig(sink_host="s")), ENV)


class ConfigTests(unittest.TestCase):
    def test_round_trip_and_legacy(self):
        cfg = RemoteConfig(enabled=True, host="h", sink_host="s", sink_port=6001)
        back = parse_remotes([asdict(cfg)])[0]
        self.assertEqual((back.sink_host, back.sink_port), ("s", 6001))
        self.assertEqual(RemoteConfig.from_dict({"host": "h"}).sink_host, "")

    def test_sink_only_row_is_not_empty(self):
        self.assertFalse(RemoteConfig(sink_host="s").is_empty())


class WidgetTests(unittest.TestCase):
    def test_edge_widget_round_trips_sink(self):
        from PyQt6.QtWidgets import QApplication
        from ui.remote_config_widget import RemoteConfigWidget
        QApplication.instance() or QApplication([])
        w = RemoteConfigWidget("edge", RemoteConfig(sink_host="s", sink_port=6002))
        c = w.to_config()
        self.assertEqual((c.sink_host, c.sink_port), ("s", 6002))
        w2 = RemoteConfigWidget("siem", RemoteConfig(sink_host="s"))
        self.assertEqual(w2.to_config().sink_host, "")


if __name__ == "__main__":
    unittest.main()
