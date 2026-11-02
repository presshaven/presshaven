"""The pattern dropdown shared by the Attack Simulation and Segmentation
Validation pages (ui.pattern_picker.PatternPickerButton):

* carries a footer reminder pointing at the Pattern Database page as where more
  patterns come from, and
* actually gains/loses a row when a pattern is enabled/disabled there -- i.e.
  the ``reload_patterns()`` path (active_presets -> group_presets -> set_groups)
  adds and removes patterns in step with the registry toggles.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.patterns import group_presets  # noqa: E402
from core.pattern_registry import (  # noqa: E402
    PatternRegistry, active_presets, load_catalog,
)
from ui.pattern_picker import PatternPickerButton, preset_key  # noqa: E402

_app = QApplication.instance() or QApplication([])


def _groups(registry):
    """Exactly what both pages feed the picker in reload_patterns()."""
    return group_presets(active_presets(registry=registry))


class PatternPickerReminderTests(unittest.TestCase):
    def test_footer_points_at_the_pattern_database(self):
        for mode in ("single", "multi"):
            with self.subTest(mode=mode):
                picker = PatternPickerButton(mode=mode)
                text = picker._popup.footer.text()
                self.assertIn("Pattern Database", text)
                # It must read as "where more patterns come from", not a warning.
                self.assertRegex(text.lower(), r"enable|add")


class PatternPickerRegistrySyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "registry.json"
        self.registry = PatternRegistry.load(self.tmp)
        # Pick a preset that is active out of the box (some CVE patterns ship
        # disabled by default) and is backed by a catalogue pattern we can
        # toggle. Chosen dynamically so the test survives catalogue edits.
        catalog = load_catalog(self.registry)
        by_cve = {p.get("cve"): p["id"] for p in catalog.patterns if p.get("cve")}
        self.preset = None
        for preset in active_presets(registry=self.registry):
            if getattr(preset, "cve", "") in by_cve:
                self.preset = preset
                self.pattern_id = by_cve[preset.cve]
                break
        self.assertIsNotNone(self.preset, "no catalogue-backed active preset to test")
        self.key = preset_key(self.preset)

    def _reload(self):
        """Re-read the registry from disk (as the live app does after the
        Pattern Database saves) and repopulate the picker."""
        registry = PatternRegistry.load(self.tmp)
        self.picker.set_groups(_groups(registry))
        return registry

    def test_disabling_removes_and_enabling_restores_the_row(self):
        self.picker = PatternPickerButton(mode="multi")
        self.picker.set_groups(_groups(self.registry))
        self.assertIn(self.key, self.picker._rows,
                      "an enabled pattern should appear in the dropdown")

        # Disable it on the Pattern Database page (registry.set_enabled + save).
        self.registry.set_enabled(self.pattern_id, False)
        self.registry.save()
        self._reload()
        self.assertNotIn(self.key, self.picker._rows,
                         "a disabled pattern must drop out of the dropdown")

        # Re-enable it: it must come back.
        registry = PatternRegistry.load(self.tmp)
        registry.set_enabled(self.pattern_id, True)
        registry.save()
        self._reload()
        self.assertIn(self.key, self.picker._rows,
                      "re-enabling a pattern must restore it to the dropdown")

    def test_single_mode_stays_in_sync_too(self):
        self.picker = PatternPickerButton(mode="single")
        self.picker.set_groups(_groups(self.registry))
        self.assertIn(self.key, self.picker._rows)
        self.registry.set_enabled(self.pattern_id, False)
        self.registry.save()
        self._reload()
        self.assertNotIn(self.key, self.picker._rows)


if __name__ == "__main__":
    unittest.main()
