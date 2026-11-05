"""Domain-reminder: which uploaded .env variables count as 'still localhost'."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.domain_check import localhost_domain_vars


class DomainCheckTests(unittest.TestCase):
    def test_edge_localhost_defaults_flagged(self):
        text = "WP_SITE_URL=http://localhost\nTRUSTED_CALLBACK_DOMAINS=http://localhost,https://localhost\n"
        self.assertEqual(localhost_domain_vars(text, "edge"),
                         ["WP_SITE_URL", "TRUSTED_CALLBACK_DOMAINS"])

    def test_real_domain_not_flagged(self):
        text = "WP_SITE_URL=https://shop.example.org\nTRUSTED_CALLBACK_DOMAINS=http://localhost,https://iairu.com\n"
        self.assertEqual(localhost_domain_vars(text, "edge"), [])

    def test_siem_placeholder_and_generic_keys(self):
        self.assertEqual(localhost_domain_vars("VECTOR_HOST=your-siem-vm.example.com\n", "edge"),
                         ["VECTOR_HOST"])
        self.assertEqual(localhost_domain_vars("KIBANA_PUBLIC_URL=http://127.0.0.1:5601\n", "siem"),
                         ["KIBANA_PUBLIC_URL"])
        self.assertEqual(localhost_domain_vars("ELASTIC_USERNAME=elastic\n", "siem"), [])

    def test_unset_not_flagged(self):
        self.assertEqual(localhost_domain_vars("WP_SITE_URL=\n", "edge"), [])


class BannerTests(unittest.TestCase):
    def test_banner_shows_and_hides(self):
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(["t"])
        from ui.domain_reminder import DomainReminderBanner, notify_env_uploaded
        b = DomainReminderBanner()
        notify_env_uploaded("edge", "WP_SITE_URL=http://localhost\n")
        self.assertFalse(b.isHidden())
        self.assertIn("WP_SITE_URL", b.label.text())
        notify_env_uploaded("edge", "WP_SITE_URL=https://a.example.org\n")
        self.assertTrue(b.isHidden())


if __name__ == "__main__":
    unittest.main()
