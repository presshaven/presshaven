"""Every service in the edge compose file must be off Compose's implicit
`default` network: its auto-allocated subnet can collide with the pinned
172.2x.0.0/24 networks and make `up` fail with "Pool overlaps"."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

EDGE = Path(__file__).resolve().parent.parent.parent / "ids"


@unittest.skipUnless(shutil.which("docker"), "docker not available")
class NoImplicitDefaultNetwork(unittest.TestCase):
    def test_no_service_uses_the_default_network(self):
        r = subprocess.run(["docker", "compose", "--profile", "*", "config", "--format", "json"],
                           cwd=EDGE, capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("compose config unavailable here")
        services = json.loads(r.stdout)["services"]
        offenders = [n for n, s in services.items()
                     if not s.get("network_mode") and
                     (not s.get("networks") or "default" in s["networks"])]
        self.assertEqual(offenders, [], f"services on the implicit default network: {offenders}")


@unittest.skipUnless(shutil.which("docker"), "docker not available")
class StacksDoNotShareSubnets(unittest.TestCase):
    """The edge and SIEM stacks can share one Docker host; every network either
    defines must be pinned, and no two may overlap."""

    @staticmethod
    def _subnets(directory):
        r = subprocess.run(["docker", "compose", "--profile", "*", "config", "--format", "json"],
                           cwd=directory, capture_output=True, text=True)
        if r.returncode != 0:
            return None
        out = {}
        for name, net in (json.loads(r.stdout).get("networks") or {}).items():
            cfg = ((net or {}).get("ipam") or {}).get("config") or []
            out[name] = [c["subnet"] for c in cfg if c.get("subnet")]
        return out

    def test_every_network_is_pinned_and_disjoint(self):
        import ipaddress
        edge = self._subnets(EDGE)
        siem = self._subnets(EDGE.parent / "siem" / "docker")
        if edge is None or siem is None:
            self.skipTest("compose config unavailable here")
        stacks = (("edge", edge), ("siem", siem))
        nets = [(f"{stack}:{n}", ipaddress.ip_network(sn))
                for stack, d in stacks for n, subs in d.items() if n != "default"
                for sn in subs]
        unpinned = [f"{stack}:{n}" for stack, d in stacks
                    for n, subs in d.items() if n != "default" and not subs]
        self.assertEqual(unpinned, [], f"networks without a pinned subnet: {unpinned}")
        for i, (a, na) in enumerate(nets):
            for b, nb in nets[i + 1:]:
                self.assertFalse(na.overlaps(nb), f"{a} {na} overlaps {b} {nb}")


class PoolManagerImageHasItsModules(unittest.TestCase):
    """manager.py imports sibling modules; the Dockerfile copies files by name,
    so a new module that is not listed there only fails once the image is
    rebuilt (remote deploys) with "No module named ...". Catch it here."""

    def test_every_local_import_is_copied_into_the_image(self):
        import ast
        import re
        pm = EDGE / "images" / "pool_manager"
        local = {p.stem for p in pm.glob("*.py") if not p.name.startswith("test_")}
        copied = set()
        for m in re.finditer(r"^COPY\s+(.+?)\s+\./?\s*$", (pm / "Dockerfile").read_text(), re.M):
            copied |= {Path(f).stem for f in m.group(1).split() if f.endswith(".py")}
        # Follow imports transitively from the entrypoint.
        needed, todo = set(), ["manager"]
        while todo:
            mod = todo.pop()
            if mod in needed:
                continue
            needed.add(mod)
            for node in ast.walk(ast.parse((pm / f"{mod}.py").read_text())):
                names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                todo += [n.split(".")[0] for n in names if n.split(".")[0] in local]
        self.assertEqual(sorted(needed - copied), [],
                         "imported by pool_manager but not COPYed in its Dockerfile")
