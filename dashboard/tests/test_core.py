"""Unit tests for the dashboard's Qt-free core modules.

Stdlib unittest only, so they run without the app's PyQt6 venv:

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DASHBOARD_DIR.parent
sys.path.insert(0, str(DASHBOARD_DIR))

from core import cert_ctl, pattern_log_parser  # noqa: E402
from core.colors import BLUE, GREEN, RED  # noqa: E402
from core.env_file import EnvFile, seed_from_example  # noqa: E402
from core.line_buffer import LineBuffer  # noqa: E402


class EnvFileTests(unittest.TestCase):
    def test_real_templates_round_trip_byte_identical(self):
        # The editor promises to keep every comment and blank line intact.
        for rel in ("ids/.env.example", "siem/docker/.env.example"):
            path = REPO_ROOT / rel
            with self.subTest(template=rel):
                self.assertEqual(EnvFile.load(path).render(), path.read_text())

    def test_set_changes_only_the_value(self):
        text = "# header\nA=1  # keep me\nB='x # not a comment'\n"
        ef = EnvFile.from_text(text, Path("x"))
        self.assertEqual(ef.get("B"), "'x # not a comment'")
        ef.set("A", "2")
        self.assertEqual(ef.render(), "# header\nA=2  # keep me\nB='x # not a comment'\n")

    def test_set_appends_missing_key(self):
        ef = EnvFile.from_text("A=1\n", Path("x"))
        ef.set("NEW", "v")
        self.assertEqual(ef.render(), "A=1\nNEW=v\n")

    def test_merge_inserts_missing_key_with_its_comment_in_place(self):
        example = EnvFile.from_text("A=1\n\n# about B\nB=2\nC=3\n", Path("ex"))
        ef = EnvFile.from_text("A=real\nC=real\n", Path("x"))
        added = ef.merge_missing_from(example)
        self.assertEqual(added, ["B"])
        self.assertEqual(ef.render(), "A=real\n\n# about B\nB=2\nC=real\n")

    def test_merge_never_touches_existing_values(self):
        example = EnvFile.from_text("A=placeholder\n", Path("ex"))
        ef = EnvFile.from_text("A=secret\n", Path("x"))
        self.assertEqual(ef.merge_missing_from(example), [])
        self.assertEqual(ef.get("A"), "secret")

    def test_seed_from_example(self):
        with tempfile.TemporaryDirectory() as d:
            example = Path(d) / ".env.example"
            target = Path(d) / ".env"
            example.write_text("A=1\nB=2\n")

            ef = seed_from_example(target, example)
            self.assertEqual(ef.path, target)
            self.assertEqual(ef.as_dict(), {"A": "1", "B": "2"})
            self.assertFalse(target.exists(), "seeding must not write until save()")

            target.write_text("A=mine\n")
            ef = seed_from_example(target, example)
            self.assertEqual(ef.as_dict(), {"A": "mine", "B": "2"})
            self.assertEqual(ef.added_keys, ["B"])


class LineBufferTests(unittest.TestCase):
    def test_reassembles_split_lines(self):
        buf = LineBuffer()
        self.assertEqual(buf.feed("one\ntw"), ["one"])
        self.assertEqual(buf.feed("o\nthree"), ["two"])
        self.assertEqual(buf.feed("\n"), ["three"])

    def test_reset_drops_partial_line(self):
        buf = LineBuffer()
        buf.feed("partial")
        buf.reset()
        self.assertEqual(buf.feed("x\n"), ["x"])


class ThreatLogParserTests(unittest.TestCase):
    parse = staticmethod(pattern_log_parser.parse_line)

    def test_header_summary_outcome(self):
        ev = self.parse("[LOCATION / HEADER] route_decision='honeypot' risk_score='85', client: 1.2.3.4")
        self.assertEqual((ev.kind, ev.label, ev.score, ev.color), ("outcome", "Routed to HONEYPOT", 85, RED))

    def test_final_decision_normalizes_denominator(self):
        ev = self.parse("[FINAL DECISION] 🍯 ROUTING TO HONEYPOT | Score: 90/80 | Reason: cve")
        self.assertEqual(ev.score, 90)
        self.assertEqual(ev.detail, "Score: 90/100 | Reason: cve")

    def test_routing_stage(self):
        ev = self.parse("[ROUTING] ✅ Clean request -> PRODUCTION | Score: 0 | IP: 1.2.3.4")
        self.assertEqual(ev.kind, "routing")
        self.assertEqual(ev.color, GREEN)

    def test_signal_delta(self):
        ev = self.parse("[PATTERN ANALYZER] 🎯 CVE match (+40) | CVE-2023-28121")
        self.assertEqual((ev.kind, ev.label, ev.color), ("signal", "CVE match (+40)", RED))
        self.assertEqual(ev.detail, "CVE-2023-28121")

    def test_pre_rename_log_lines_still_parse(self):
        ev = self.parse("[THREAT ANALYZER] 🎯 CVE match (+40) | CVE-2023-28121")
        self.assertEqual((ev.kind, ev.label), ("signal", "CVE match (+40)"))
        ev = self.parse("[LOCATION / HEADER] route_decision='honeypot' threat_score='85'")
        self.assertEqual(ev.score, 85)

    def test_docker_timestamp_is_captured_through_ansi_reset(self):
        line = ("reverse_proxy-1  | \x1b[0m2026-08-09T10:32:37.684747138Z "
                "[LOCATION / HEADER] route_decision='production' risk_score='0'")
        ev = self.parse(line)
        self.assertEqual(ev.timestamp, "2026-08-09T10:32:37.684747138Z")
        self.assertEqual(ev.score, 0)

    def test_gdpr_signature_received(self):
        ev = self.parse(
            "[GDPR] Received gdpr_signature=abc123def456 | Session: s-42, client: 1.2.3.4")
        self.assertEqual((ev.kind, ev.label), ("gdpr", "GDPR signature received"))
        self.assertEqual(ev.detail, "Signature: abc123def456 | Session: s-42")
        self.assertEqual(ev.color, BLUE)

    def test_gdpr_signature_without_session_still_parses(self):
        ev = self.parse("[GDPR] Received gdpr_signature=abc123def456")
        self.assertEqual((ev.kind, ev.detail), ("gdpr", "Signature: abc123def456"))

    def test_irrelevant_lines_are_ignored(self):
        self.assertIsNone(self.parse("[SESSION DEBUG] cookie_PHPSESSID=nil"))
        self.assertIsNone(self.parse("   "))


class SignatureSimTests(unittest.TestCase):
    """core/signature_sim.extract_signature -- the pure log-scraping half of
    the Signature Simulation page's flow."""

    def setUp(self):
        from core import signature_sim
        self.sim = signature_sim
        self.extract = staticmethod(signature_sim.extract_signature).__func__

    def test_pulls_signature_and_session_from_a_proxy_log_line(self):
        log = ("reverse_proxy-1  | 2026-08-09T10:32:37.6Z [REQUEST] IP: 1.2.3.4\n"
               "reverse_proxy-1  | 2026-08-09T10:32:37.7Z [GDPR] Received "
               "gdpr_signature=abc123 | Session: s-42, client: 1.2.3.4\n")
        self.assertEqual(self.extract(log), ("abc123", "s-42"))

    def test_takes_the_most_recent_line_when_several_are_present(self):
        log = ("[GDPR] Received gdpr_signature=old | Session: s-1\n"
               "[GDPR] Received gdpr_signature=new | Session: s-2\n")
        self.assertEqual(self.extract(log), ("new", "s-2"))

    def test_signature_without_a_session(self):
        self.assertEqual(self.extract("[GDPR] Received gdpr_signature=lonely"),
                         ("lonely", ""))

    def test_no_gdpr_line_yields_empty(self):
        self.assertEqual(self.extract("[REQUEST] nothing to see here\n   "), ("", ""))

    def test_extract_all_counts_repeated_lines(self):
        # The dashboard's cookieless requests reuse one fingerprint session and a
        # given window size reproduces the same signature, so run_flow recognises
        # a new run by the LINE COUNT growing, not by either value changing.
        log = ("[GDPR] Received gdpr_signature=same | Session: s-1\n"
               "[GDPR] Received gdpr_signature=same | Session: s-1\n"
               "[GDPR] Received gdpr_signature=same | Session: s-1\n")
        pairs = self.sim.extract_all_signatures(log)
        self.assertEqual(pairs, [("same", "s-1")] * 3)
        self.assertEqual(self.extract(log), ("same", "s-1"))


class CertSubjectTests(unittest.TestCase):
    def test_edge_cert_subject_does_not_name_the_honeypot(self):
        # The blind pentest identified the deception from O=HoneypotOrg.
        calls = []
        orig_run = cert_ctl._run
        with tempfile.TemporaryDirectory() as d:
            orig_dir = cert_ctl.EDGE_SSL_CERT_DIR
            cert_ctl.EDGE_SSL_CERT_DIR = Path(d)
            cert_ctl._run = lambda args, *a, **k: (calls.append(args),
                                                    (Path(d) / "server.key").touch(),
                                                    (Path(d) / "server.crt").touch())
            try:
                cert_ctl._gen_edge_nginx_cert()
            finally:
                cert_ctl._run = orig_run
                cert_ctl.EDGE_SSL_CERT_DIR = orig_dir
        subject = calls[0][calls[0].index("-subj") + 1]
        self.assertNotIn("honeypot", subject.lower())
        compose = (REPO_ROOT / "ids" / "docker-compose.yml").read_text()
        self.assertNotIn("honeypot", compose.split("-subj", 1)[1].splitlines()[0].lower())


class ContainerStatusTests(unittest.TestCase):
    """Start-settle logic behind "Start with PDF graph export"."""

    @staticmethod
    def _c(state="running", health="", exit_code="0"):
        return {"State": state, "Health": health, "ExitCode": exit_code}

    def test_health_starting_is_its_own_state(self):
        from core.container_status import RUNNING, STARTING, classify
        self.assertEqual(classify(self._c(health="starting")), STARTING)
        self.assertEqual(classify(self._c()), RUNNING)

    def test_not_settled_while_up_is_still_running(self):
        # All visible containers look ready, but `up -d` hasn't exited: later
        # services may still be waiting on their dependencies.
        from core.container_status import start_settled
        ready = [self._c(health="healthy"), self._c(state="exited")]
        self.assertFalse(start_settled(ready, None))
        self.assertTrue(start_settled(ready, 0))

    def test_not_settled_while_a_database_is_in_start_period(self):
        from core.container_status import start_settled
        containers = [self._c(health="healthy"), self._c(health="starting")]
        self.assertFalse(start_settled(containers, 0))

    def test_not_settled_while_a_container_is_only_created(self):
        from core.container_status import start_settled
        self.assertFalse(start_settled([self._c(state="created")], 0))

    def test_unhealthy_or_crashed_counts_as_settled(self):
        # Waiting longer won't change these; the report should show them.
        from core.container_status import start_settled
        self.assertTrue(start_settled([self._c(health="unhealthy")], 0))
        self.assertTrue(start_settled([self._c(state="exited", exit_code="1")], 0))

    def test_failed_up_settles_even_with_created_dependents(self):
        from core.container_status import start_settled
        self.assertTrue(start_settled([self._c(state="created")], 1))

    def test_empty_listing_is_not_settled(self):
        from core.container_status import start_settled
        self.assertFalse(start_settled([], 0))

    def test_summary_counts_starting_as_not_up(self):
        from core.container_status import summarize
        text, _ = summarize([self._c(health="healthy"), self._c(health="starting")])
        self.assertEqual(text, "1/2 up (1 starting)")


class PurgeTests(unittest.TestCase):
    def test_edge_purge_removes_runtime_pools_before_down(self):
        from core.docker_ctl import Target
        argv, _ = Target(project="edge").build_purge()
        self.assertEqual(argv[:2], ["sh", "-c"])
        cmd = argv[2]
        stop = cmd.index("stop pool_manager")
        rm = cmd.index("docker rm -f -v")
        vol = cmd.index("docker volume rm -f")
        down = cmd.index("down -v --remove-orphans")
        self.assertLess(stop, rm)
        self.assertLess(rm, vol)
        self.assertLess(vol, down)
        self.assertIn("label=honeypot.pool.managed-by=pool_manager", cmd)

    def test_siem_purge_is_plain_down(self):
        from core.docker_ctl import Target
        argv, _ = Target(project="siem").build_purge()
        self.assertEqual(argv[:2], ["docker", "compose"])
        self.assertEqual(argv[-3:], ["down", "-v", "--remove-orphans"])


class PruneOrphanRulesTests(unittest.TestCase):
    """Target.prune_orphan_rules() is the deploy hook that clears host iptables
    rules Docker orphaned on a previous teardown: a `! -i <dead-bridge>` DROP
    matches every packet, so it blackholes the reused container IP and
    production_db_seed could never reach production_database. It runs the host
    script locally and is a no-op for a remote target."""

    def test_remote_target_is_a_noop(self):
        from core.docker_ctl import Target
        from core.state import RemoteConfig
        with mock.patch.object(subprocess, "run") as run:
            out = Target(project="edge",
                         remote=RemoteConfig(host="host.example")).prune_orphan_rules()
        self.assertEqual(out, "")
        run.assert_not_called()

    def test_local_target_runs_the_prune_script(self):
        from core import paths
        from core.docker_ctl import Target
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[prune-iptables] done\n", stderr="")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            out = Target(project="edge").prune_orphan_rules()
        self.assertIn("[prune-iptables] done", out)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "sh")
        self.assertEqual(argv[1], str(paths.EDGE_DIR / "scripts" / "prune_orphan_iptables.sh"))

    def test_failure_is_non_fatal(self):
        from core.docker_ctl import Target
        with mock.patch.object(subprocess, "run", side_effect=OSError("boom")):
            out = Target(project="edge").prune_orphan_rules()
        self.assertIn("skipped", out)


class RuntimePoolRecordTests(unittest.TestCase):
    """_pool_record maps a `docker ps --format json` record for a runtime
    honeypot pool onto the compose-ps field names ps() / the Health diagram
    read, and filters out anything that isn't a pool's serving container."""

    def _raw(self, name, state="running", health="healthy",
             status="Up 2 minutes (healthy)"):
        return {"Names": name, "State": state, "HealthStatus": health,
                "Status": status, "CreatedAt": "2026-10-22 09:00:00 +0000 UTC",
                "Image": "honeypot/eshop:latest"}

    def test_running_eshop_pool_is_reshaped(self):
        from core.docker_ctl import _pool_record
        rec = _pool_record(self._raw("honeypot_eshop_4"))
        self.assertEqual(rec["Service"], "honeypot_eshop_4")
        self.assertEqual(rec["Name"], "honeypot_eshop_4")
        self.assertEqual(rec["State"], "running")
        self.assertEqual(rec["Health"], "healthy")   # docker ps's HealthStatus
        self.assertEqual(rec["ExitCode"], "0")
        self.assertEqual(rec["CreatedAt"], "2026-10-22 09:00:00 +0000 UTC")

    def test_database_pool_is_reshaped(self):
        from core.docker_ctl import _pool_record
        rec = _pool_record(self._raw("honeypot_database_5", status="Up 1 minute"))
        self.assertEqual(rec["Service"], "honeypot_database_5")

    def test_exit_code_parsed_from_status(self):
        from core.docker_ctl import _pool_record
        rec = _pool_record(self._raw("honeypot_eshop_4", state="exited",
                                     health="", status="Exited (137) 3 seconds ago"))
        self.assertEqual(rec["ExitCode"], "137")

    def test_provisioning_helper_is_skipped(self):
        # Short-lived scale-up helpers carry the same pool label but get
        # random Docker-assigned names -- they must not surface as pools.
        from core.docker_ctl import _pool_record
        self.assertIsNone(_pool_record(self._raw("eager_banana")))
        self.assertIsNone(_pool_record(self._raw("honeypot_eshop_4_helper")))

    def test_first_name_wins_when_comma_joined(self):
        from core.docker_ctl import _pool_record
        rec = _pool_record(self._raw("honeypot_eshop_4,some-alias"))
        self.assertEqual(rec["Service"], "honeypot_eshop_4")


if __name__ == "__main__":
    unittest.main()


class FinishedOkTests(unittest.TestCase):
    def test_only_cleanly_exited_jobs_are_cleaned_up(self):
        from core.container_status import finished_ok
        cs = [{"Service": "init-password", "State": "exited", "ExitCode": 0},
              {"Service": "kibana_dashboards_setup", "State": "exited", "ExitCode": 1},
              {"Service": "kibana", "State": "running", "ExitCode": 0}]
        self.assertEqual([c["Service"] for c in finished_ok(cs)], ["init-password"])


class RemoteHostsModelTests(unittest.TestCase):
    """Per-project lists of SSH hosts: legacy single-remote migration, the
    primary/configured accessors, targets_for() fan-out with unique keys, and
    the settings-bundle round trip. See core/state.py and core/docker_ctl.py."""

    def _state_from(self, raw: dict):
        import json as _json
        from core import state as state_mod
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            path.write_text(_json.dumps(raw))
            with mock.patch.object(state_mod, "STATE_FILE", path):
                return state_mod.AppState.load()

    def test_legacy_single_dict_migrates_to_one_element_list(self):
        s = self._state_from({"remote_edge": {
            "enabled": True, "host": "h1", "user": "u", "key_path": "/k"}})
        self.assertEqual([r.host for r in s.remotes_for("edge")], ["h1"])
        self.assertEqual(s.remotes_for("siem"), [])

    def test_untouched_legacy_default_dict_collapses_to_empty(self):
        s = self._state_from({"remote_edge": {
            "enabled": False, "host": "", "port": 22, "user": "",
            "key_path": "", "remote_path": ""}})
        self.assertEqual(s.remotes_for("edge"), [])

    def test_new_list_format_loads_and_drops_blank_rows(self):
        s = self._state_from({"remote_edge": [
            {"enabled": True, "host": "h1", "user": "u", "key_path": "/k"},
            {"enabled": False, "host": "", "user": "", "key_path": ""},
            {"enabled": True, "host": "h2", "user": "u", "key_path": "/k"},
        ]})
        self.assertEqual([r.host for r in s.remotes_for("edge")], ["h1", "h2"])

    def test_primary_and_configured_skip_unconfigured(self):
        from core.state import AppState, RemoteConfig
        s = AppState()
        s.set_remotes("edge", [
            RemoteConfig(enabled=False, host="off", user="u", key_path="/k"),
            RemoteConfig(enabled=True, host="on1", user="u", key_path="/k"),
            RemoteConfig(enabled=True, host="on2", user="u", key_path="/k"),
        ])
        self.assertEqual([r.host for r in s.configured_remotes("edge")], ["on1", "on2"])
        self.assertEqual(s.primary_remote("edge").host, "on1")
        self.assertEqual(s.primary_remote_host("edge"), "on1")

    def test_primary_remote_host_falls_back_when_local_only(self):
        from core.state import AppState
        s = AppState()
        self.assertIsNone(s.primary_remote("edge"))
        self.assertEqual(s.primary_remote_host("edge"), "localhost")
        self.assertEqual(s.primary_remote_host("edge", "127.0.0.1"), "127.0.0.1")

    def test_targets_for_fans_out_local_plus_each_remote_with_unique_keys(self):
        from core.docker_ctl import targets_for
        from core.state import AppState, RemoteConfig
        s = AppState()
        s.set_remotes("edge", [
            RemoteConfig(enabled=True, host="h1", user="u", key_path="/k"),
            RemoteConfig(enabled=True, host="h2", user="u", key_path="/k"),
        ])
        targets = targets_for("edge", s)
        self.assertEqual([t.is_remote for t in targets], [False, True, True])
        keys = [t.key for t in targets]
        self.assertEqual(len(keys), len(set(keys)), keys)

    def test_bundle_exports_a_list_that_parse_remotes_reconstructs(self):
        # export_bundle only reads .env files; the destructive apply_bundle
        # (which writes real .env files) is deliberately not exercised here.
        from core.settings_bundle import export_bundle
        from core.state import AppState, RemoteConfig, parse_remotes
        src = AppState()
        src.set_remotes("edge", [
            RemoteConfig(enabled=True, host="h1", user="u", key_path="/k", name="a"),
            RemoteConfig(enabled=True, host="h2", user="u", key_path="/k", name="b"),
        ])
        bundle = export_bundle(src)
        self.assertIsInstance(bundle["remote_edge"], list)
        self.assertEqual(bundle["remote_siem"], [])
        restored = parse_remotes(bundle["remote_edge"])
        self.assertEqual([(r.host, r.name) for r in restored],
                         [("h1", "a"), ("h2", "b")])

    def test_display_name_prefers_name_then_host(self):
        from core.state import RemoteConfig
        self.assertEqual(RemoteConfig(name="label", host="h").display_name, "label")
        self.assertEqual(RemoteConfig(host="h").display_name, "h")
        self.assertEqual(RemoteConfig().display_name, "remote")
