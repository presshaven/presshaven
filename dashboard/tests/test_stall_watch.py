import tempfile
import threading
import time
import unittest
from pathlib import Path

from core.stall_watch import StallWatch


class StallWatchTests(unittest.TestCase):
    def test_reports_once_with_gui_stack(self):
        with tempfile.TemporaryDirectory(prefix="pfwtest_") as d:
            w = StallWatch(threading.get_ident(), Path(d), threshold=0.05)
            w.beat()
            self.assertIsNone(w.check_once())          # fresh heartbeat
            time.sleep(0.1)
            path = w.check_once()
            self.assertIsNotNone(path)
            self.assertIn("test_reports_once_with_gui_stack", path.read_text())
            self.assertIsNone(w.check_once())          # same stall: not again
            w.beat(); time.sleep(0.1)
            self.assertIsNotNone(w.check_once())       # a new stall reports


if __name__ == "__main__":
    unittest.main()
