"""Tests for ntlmscout's catch-all (path-agnostic) NTLM detection.

A host that enforces NTLM on *every* path (an IIS site-wide Windows Auth
filter, or an ADC / reverse proxy in front of the app) answers the whole
endpoint wordlist with a 401+NTLM challenge, so the discovered "endpoints"
are just the wordlist enumerating itself. The canary probe detects this and
collapses the false positives to a single, honest finding.
"""
import argparse
import unittest

import ntlmscout as ns


def _http(host, url, ntlm=True, port=443, proto="https", fingerprint=None):
    return {
        "target": url, "protocol": proto, "host": host, "port": port,
        "url": url, "success": True,
        "ntlm": {"target_name": "fd"} if ntlm else None,
        "fingerprint": fingerprint or {"netbios_computer": "HOST01"},
    }


def _canary(host, port=443, proto="https"):
    url = "{}://{}:{}{}".format(proto, host, port, ns.canary_path())
    return _http(host, url, ntlm=True, port=port, proto=proto)


class CanaryPathTests(unittest.TestCase):
    def test_canary_path_carries_marker(self):
        self.assertIn(ns.CANARY_MARKER, ns.canary_path())

    def test_canary_paths_are_unique(self):
        self.assertNotEqual(ns.canary_path(), ns.canary_path())

    def test_is_canary_result_matches_marker(self):
        self.assertTrue(ns.is_canary_result(_canary("h.example")))
        self.assertFalse(ns.is_canary_result(_http("h.example", "https://h.example/owa/")))


class CollapseCatchallTests(unittest.TestCase):
    def test_collapses_wordlist_to_one_endpoint_when_canary_challenges(self):
        host = "authwall.example"
        results = [_canary(host)]
        for path in ("/", "/owa/", "/EWS/Exchange.asmx", "/adfs/ls/"):
            results.append(_http(host, "https://" + host + path))

        out = ns.collapse_catchall_endpoints(results)

        # The synthetic canary path is never reported as an endpoint.
        self.assertFalse(any(ns.is_canary_result(r) for r in out))
        # Exactly one NTLM-bearing endpoint remains for this host:port.
        ntlm = [r for r in out if r.get("ntlm")]
        self.assertEqual(len(ntlm), 1)
        self.assertTrue(ntlm[0]["catchall"])
        self.assertEqual(ntlm[0]["catchall_collapsed"], 4)
        # The rest are still present (they may carry disclosed names) but are
        # no longer counted as NTLM endpoints.
        collapsed = [r for r in out if r.get("catchall") and not r.get("ntlm")]
        self.assertEqual(len(collapsed), 3)

    def test_representative_prefers_site_root(self):
        host = "h.example"
        results = [
            _canary(host),
            _http(host, "https://h.example/owa/"),
            _http(host, "https://h.example/"),
            _http(host, "https://h.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        rep = [r for r in out if r.get("ntlm")][0]
        self.assertEqual(rep["url"], "https://h.example/")

    def test_no_collapse_when_canary_does_not_challenge(self):
        host = "normal.example"
        results = [
            _http(host, "https://normal.example" + ns.canary_path(), ntlm=False),
            _http(host, "https://normal.example/owa/"),
            _http(host, "https://normal.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        self.assertEqual(sum(1 for r in out if r.get("ntlm")), 2)
        self.assertFalse(any(r.get("catchall") for r in out))

    def test_other_hosts_are_untouched(self):
        catchall_host, normal_host = "a.example", "b.example"
        results = [
            _canary(catchall_host),
            _http(catchall_host, "https://a.example/owa/"),
            _http(catchall_host, "https://a.example/"),
            _http(normal_host, "https://b.example/owa/"),
            _http(normal_host, "https://b.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        normal = [r for r in out if r["host"] == normal_host and r.get("ntlm")]
        self.assertEqual(len(normal), 2)
        self.assertFalse(any(r.get("catchall") for r in normal))

    def test_non_http_results_are_untouched(self):
        host = "h.example"
        smb = {"target": "h.example:445", "protocol": "smb", "host": host,
               "port": 445, "url": None, "success": True,
               "ntlm": {"target_name": "fd"}, "fingerprint": {}}
        results = [_canary(host), _http(host, "https://h.example/owa/"), smb]
        out = ns.collapse_catchall_endpoints(results)
        self.assertTrue([r for r in out if r["protocol"] == "smb"][0].get("ntlm"))


class PlanTargetsCanaryTests(unittest.TestCase):
    def _args(self, targets, no_discover=False):
        return argparse.Namespace(targets=targets, input_list=None,
                                  no_discover=no_discover, no_internal_ip=True)

    def test_adds_one_canary_per_http_endpoint_when_discovering(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"]))
        canaries = [j for j in jobs if ns.CANARY_MARKER in (j[3] or "")]
        self.assertEqual(len(canaries), 1)
        # Wordlist paths are still planned alongside the canary.
        self.assertEqual(len(jobs), len(ns.HTTP_PATHS) + 1)

    def test_no_canary_without_discovery(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"], no_discover=True))
        self.assertFalse(any(ns.CANARY_MARKER in (j[3] or "") for j in jobs))


if __name__ == "__main__":
    unittest.main()
