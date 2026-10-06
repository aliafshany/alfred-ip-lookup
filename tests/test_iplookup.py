#!/usr/bin/python3
"""Offline tests for the IP Lookup Alfred workflow."""

import datetime
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "iplookup", os.path.join(ROOT, "workflow", "iplookup.py")
)
ipk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ipk)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "checkhost-8.8.8.8.html")


class ParseTests(unittest.TestCase):
    def test_checkhost_fixture(self):
        with open(FIXTURE, "r", encoding="utf-8") as handle:
            page = handle.read()
        records = ipk.parse_checkhost(page)
        self.assertEqual(len(records), 5)
        self.assertTrue(all(rec["country_code"] == "US" for rec in records))
        self.assertTrue(all(rec["country"].startswith("United States") for rec in records))
        self.assertTrue(all(rec["asn"] == "15169" for rec in records))
        names = [rec["name"] for rec in records]
        self.assertIn("DB-IP", names)
        self.assertTrue(any("MaxMind" in name for name in names))
        for rec in records:
            self.assertIsInstance(rec["date"], datetime.date)
        dbip = next(rec for rec in records if rec["name"] == "DB-IP")
        self.assertEqual(dbip["date"], datetime.date(2026, 10, 5))
        self.assertEqual(dbip["city"], "Mountain View")
        self.assertEqual(dbip["label"], "DB-IP (05.10.2026)")
        self.assertEqual(dbip["source"], "check-host")

    def test_query_forms(self):
        cases = {
            "8.8.8.8:443": "8.8.8.8",
            "https://1.1.1.1/x": "1.1.1.1",
            "[2606:4700::1111]:443": "2606:4700::1111",
            "ip=5.160.0.1,": "5.160.0.1",
            "۸.۸.۸.۸": "8.8.8.8",
            "٨.٨.٨.٨": "8.8.8.8",
            "2001:4860:4860::8888": "2001:4860:4860::8888",
        }
        for text, expected in cases.items():
            parsed = ipk.parse_query(text)
            self.assertEqual(parsed["kind"], "ip", text)
            self.assertEqual(parsed["ip"], expected, text)
        self.assertEqual(ipk.parse_query("8.8.")["kind"], "incomplete")
        self.assertEqual(ipk.parse_query("10.0.0.1")["kind"], "private")
        self.assertEqual(ipk.parse_query("100.64.1.1")["kind"], "private")
        self.assertEqual(ipk.parse_query("127.0.0.1")["kind"], "private")
        self.assertEqual(ipk.parse_query("")["kind"], "empty")
        host = ipk.parse_query("https://example.com/x")
        self.assertEqual(host["kind"], "host")
        self.assertEqual(host["host"], "example.com")

    def test_flags(self):
        self.assertEqual(ipk.flag_emoji("DE"), "🇩🇪")
        self.assertEqual(ipk.flag_emoji("IR"), "🇮🇷")
        self.assertEqual(ipk.flag_emoji("de"), ipk.flag_emoji("DE"))

    def test_isp_normalization(self):
        forms = [
            "Google Llc",
            "GOOGLE LLC (Private Customer)",
            "AS15169 GOOGLE LLC",
        ]
        keys = [ipk.isp_key(form) for form in forms]
        self.assertTrue(keys[0])
        self.assertEqual(len(set(keys)), 1)
        self.assertNotIn("limited", keys[0])
        self.assertNotIn("15169", keys[0])

    def test_consensus_disagreement(self):
        records = []
        for _ in range(7):
            records.append(
                {
                    "country": "United States",
                    "country_code": "US",
                    "isp": "GOOGLE LLC",
                    "asn": "15169",
                    "city": "Mountain View",
                    "label": "db",
                    "elapsed_ms": 100,
                }
            )
        for _ in range(2):
            records.append(
                {
                    "country": "Iran",
                    "country_code": "IR",
                    "isp": "Example Telecom",
                    "asn": "1",
                    "city": "Tehran",
                    "label": "other",
                    "elapsed_ms": 200,
                }
            )
        summary = ipk.build_summary("8.8.8.8", records)
        self.assertTrue(summary["title"].startswith("⚠️ "))
        self.assertIn("🇺🇸 United States", summary["title"])
        self.assertIn("country 7/9 · ISP 7/9 agree", summary["subtitle"])
        self.assertIn("AS15169", summary["subtitle"])
        self.assertIn("United States (US)", summary["arg"])
        self.assertIn("GOOGLE LLC (AS15169)", summary["arg"])

    def test_rdap_longest_prefix(self):
        services = [
            [
                ["10.0.0.0/8", "8.8.0.0/16"],
                ["https://rdap.db.ripe.net/"],
            ],
            [
                ["8.8.8.0/24"],
                ["https://rdap.example.net/"],
            ],
            [
                ["2001:4860::/32"],
                ["https://rdap.arin.net/registry/"],
            ],
            [
                ["2001:4860:4860::/48"],
                ["http://rdap.slow.example/", "https://rdap.arin.net/registry/v6/"],
            ],
        ]
        self.assertEqual(
            ipk.match_rdap(services, "8.8.8.8"),
            "https://rdap.example.net/",
        )
        self.assertEqual(
            ipk.match_rdap(services, "8.8.1.1"),
            "https://rdap.db.ripe.net/",
        )
        self.assertIsNone(ipk.match_rdap(services, "9.9.9.9"))
        self.assertEqual(
            ipk.match_rdap(services, "2001:4860:4860::8888"),
            "https://rdap.arin.net/registry/v6/",
        )
        self.assertEqual(
            ipk.rdap_query_url("https://rdap.db.ripe.net/", "8.8.8.8"),
            "https://rdap.db.ripe.net/ip/8.8.8.8",
        )


class FilterCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iplookup-test-")
        self._env = os.environ.get("alfred_workflow_cache")
        os.environ["alfred_workflow_cache"] = self.tmp
        self.spawned = []
        self._spawn = ipk.spawn_fetch
        ipk.spawn_fetch = lambda args: self.spawned.append(list(args))
        self._curl = ipk.curl
        ipk.curl = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network"))

    def tearDown(self):
        ipk.spawn_fetch = self._spawn
        ipk.curl = self._curl
        if self._env is None:
            os.environ.pop("alfred_workflow_cache", None)
        else:
            os.environ["alfred_workflow_cache"] = self._env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, directory, name, obj):
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            if isinstance(obj, str):
                handle.write(obj)
            else:
                json.dump(obj, handle)

    def _geo(self, label, elapsed):
        return {
            "ok": True,
            "label": label,
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "isp": "GOOGLE LLC",
            "asn": "15169",
            "elapsed_ms": elapsed,
        }

    def test_partial_cache_reruns(self):
        directory = ipk.lookup_dir("8.8.8.8")
        self._write(directory, "started", "1")
        self._write(
            directory,
            "ip-api.json",
            self._geo("ip-api.com", 90),
        )
        payload = ipk.script_filter("8.8.8.8")
        self.assertEqual(payload.get("rerun"), 0.2)
        titles = [item["title"] for item in payload["items"]]
        self.assertTrue(any(title.startswith("⏳") for title in titles))
        self.assertIn("ipinfo.io", titles[-1])
        self.assertIn("RDAP", titles[-1])
        self.assertNotIn("uid", payload["items"][0])
        self.assertEqual(payload["items"][0]["icon"]["path"], "icon.png")
        self.assertTrue(payload["items"][0]["valid"])
        self.assertIn("United States", payload["items"][0]["title"])
        self.assertEqual(self.spawned, [])

    def test_complete_cache_no_rerun(self):
        directory = ipk.lookup_dir("1.1.1.1")
        self._write(directory, "started", "1")
        self._write(
            directory,
            "check-host.json",
            {
                "ok": True,
                "elapsed_ms": 50,
                "records": [self._geo("DB-IP (05.10.2026)", 50)],
            },
        )
        self._write(directory, "ip-api.json", self._geo("ip-api.com", 40))
        self._write(directory, "ipapi-is.json", self._geo("ipapi.is", 60))
        self._write(directory, "ipwho-is.json", self._geo("ipwho.is", 70))
        self._write(directory, "ipinfo.json", self._geo("ipinfo.io (live)", 80))
        self._write(
            directory,
            "rdap.json",
            {
                "ok": True,
                "kind": "rdap",
                "country": "AU",
                "name": "APNIC-LABS",
                "org": "APNIC Research and Development",
                "cidr": "1.1.1.0/24",
                "rir": "APNIC",
                "handle": "1.1.1.0 - 1.1.1.255",
            },
        )
        self._write(directory, "done", "1")
        now = os.path.getmtime(os.path.join(directory, "done"))
        os.utime(os.path.join(directory, "started"), (now - 5, now - 5))
        payload = ipk.script_filter("1.1.1.1")
        self.assertNotIn("rerun", payload)
        blob = json.dumps(payload)
        self.assertNotIn("⏳", blob)
        self.assertTrue(payload["items"][0]["title"].startswith("🇺🇸"))
        self.assertIn("all 5 sources agree", payload["items"][0]["subtitle"])
        self.assertTrue(any(item["title"].startswith("📋 ") for item in payload["items"]))
        self.assertEqual(self.spawned, [])
        for item in payload["items"]:
            self.assertNotIn("uid", item)
            self.assertEqual(item["icon"]["path"], "icon.png")
        summary = payload["items"][0]
        self.assertIn("check-host.net", summary["mods"]["cmd"]["arg"])
        self.assertIn("ipinfo.io/1.1.1.1", summary["mods"]["alt"]["arg"])
        self.assertEqual(summary["quicklookurl"], summary["mods"]["cmd"]["arg"])


if __name__ == "__main__":
    unittest.main()
