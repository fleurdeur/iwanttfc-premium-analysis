#!/usr/bin/env python3
"""
Offline test suite for iwant_bypass.py.

Run:
    python -m unittest test_iwant_bypass -v
    python iwant_bypass.py selftest

No network, no live bearer, no browser. Everything here exercises pure
functions and mocked HTTP so it is safe to run anywhere.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("iwant_bypass", HERE / "iwant_bypass.py")
iw = importlib.util.module_from_spec(spec)
sys.modules.setdefault("iwant_bypass", iw)
spec.loader.exec_module(iw)


def make_jwt(claims):
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(claims)}.sig"


class FakeResponse:
    def __init__(self, status=200, body=b"", json_obj=None, headers=None):
        self.status_code = status
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self._json = json_obj
        self.headers = headers or {}

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class UrlTests(unittest.TestCase):
    def test_norm_lic_unescapes_capture_artifacts(self):
        raw = ("https://widevine-dash.ezdrm.com/proxy?pX=C47792"
               "\\u0026CustomData=a\\/b&amp;origin=iwant")
        want = ("https://widevine-dash.ezdrm.com/proxy?pX=C47792"
                "&CustomData=a/b&origin=iwant")
        self.assertEqual(iw.norm_lic(raw), want)

    def test_norm_lic_idempotent(self):
        url = "https://widevine-dash.ezdrm.com/proxy?pX=1&CustomData=abc&origin=iwant"
        self.assertEqual(iw.norm_lic(url), url)

    def test_norm_mpd(self):
        self.assertEqual(iw.norm_mpd("https://x/y\\/z.mpd"), "https://x/y/z.mpd")

    def test_lic_exp_from_url(self):
        exp = int(time.time()) + 120
        cd = make_jwt({"exp": exp, "playback_properties": {"userId": "u"}})
        url = f"https://widevine-dash.ezdrm.com/proxy?pX=1&CustomData={cd}&origin=iwant"
        self.assertEqual(iw.lic_exp_from_url(url), float(exp))

    def test_lic_exp_from_url_bad_input(self):
        self.assertEqual(iw.lic_exp_from_url("not a url"), 0.0)
        self.assertEqual(iw.lic_exp_from_url(""), 0.0)


MPD = """<?xml version="1.0"?>
<MPD type="dynamic" xmlns="urn:mpeg:dash:schema:mpd:2011">
  <BaseURL>https://cdn.example/root/</BaseURL>
  <Location>https://cdn.example/beacon?x=1&amp;y=2</Location>
  <Period><AdaptationSet><Representation>
    <SegmentTemplate initialization="init.mp4?m=1"
                     media="seg_$Number$.m4s?m=1" timescale="1000"/>
  </Representation></AdaptationSet></Period>
</MPD>"""


class ManifestTests(unittest.TestCase):
    def test_mpd_base_uses_baseurl(self):
        base = iw.mpd_base(MPD, "https://cdn.example/live/index.mpd?q=1")
        self.assertEqual(base, "https://cdn.example/root/")

    def test_mpd_base_relative_and_entities(self):
        x = '<MPD><BaseURL>a/b?x=1&amp;y=2</BaseURL></MPD>'
        self.assertEqual(iw.mpd_base(x, "https://cdn.example/live/index.mpd"),
                         "https://cdn.example/live/a/b?x=1&y=2")

    def test_mpd_base_falls_back_to_manifest(self):
        self.assertEqual(iw.mpd_base("<MPD/>", "https://cdn.example/i.mpd"),
                         "https://cdn.example/i.mpd")

    def test_rewrite_resolves_segments_against_base(self):
        out = iw.rewrite_mpd(MPD, iw.mpd_base(MPD, "https://cdn.example/live/index.mpd"))
        self.assertNotIn("<BaseURL>", out)
        self.assertNotIn("<Location>", out)
        self.assertIn("minimumUpdatePeriod", out)
        m = re.search(r'media="([^"]+)"', out)
        self.assertIsNotNone(m)
        proxied = m.group(1)
        self.assertTrue(proxied.startswith("/p/abs?u="))
        upstream = iw.unquote(proxied.split("u=", 1)[1])
        self.assertEqual(upstream, "https://cdn.example/root/seg_$Number$.m4s?m=1")

    def test_rewrite_keeps_number_template(self):
        out = iw.rewrite_mpd(MPD, "https://cdn.example/root/")
        self.assertIn("$Number$", out)

    def test_rewrite_injects_update_period_on_bare_mpd(self):
        x = '<MPD><BaseURL>https://cdn.example/root/</BaseURL></MPD>'
        out = iw.rewrite_mpd(x, iw.mpd_base(x, "https://cdn.example/i.mpd"))
        self.assertIn('minimumUpdatePeriod="PT2S"', out)
        self.assertTrue(out.startswith("<MPD minimumUpdatePeriod="))


def step(url):
    return {"url": url, "method": "GET", "body": None, "headers": {}}


class ReplayTests(unittest.TestCase):
    def test_start_first_then_api_then_pages(self):
        s = iw.Session(asset_id="a")
        s.api_chain = [step("https://www.iwanttfc.com/player/a"),
                       step("https://api.iwanttfc.com/subs/api/x"),
                       step("https://api.iwanttfc.com/entitlement/playback/start/a")]
        order = iw._replay_order(s)
        self.assertIn("playback/start", order[0]["url"])
        self.assertIn("api.iwanttfc.com", order[1]["url"])
        self.assertEqual(order[-1]["url"], "https://www.iwanttfc.com/player/a")


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.exp = int(time.time()) + 600
        self.tok = make_jwt({"uid": "U-1", "sub": "S-1", "exp": self.exp})

    def test_uid_prefers_uid_over_sub(self):
        self.assertEqual(iw._uid_from_jwt(self.tok), "U-1")

    def test_jwt_ids_reports_both(self):
        ids = iw._jwt_ids(self.tok)
        self.assertEqual(ids["jwt_uid"], "U-1")
        self.assertEqual(ids["jwt_sub"], "S-1")

    def test_jwt_exp(self):
        self.assertEqual(iw.jwt_exp(self.tok), float(self.exp))

    def test_bad_jwt_is_empty(self):
        self.assertEqual(iw._uid_from_jwt("nope"), "")
        self.assertEqual(iw.jwt_exp("nope"), 0.0)


class SessionExpiryTests(unittest.TestCase):
    def test_lic_left_uses_customdata_exp(self):
        s = iw.Session()
        s.lic_exp = time.time() + 60
        self.assertTrue(55 <= s.lic_left() <= 60)

    def test_lic_left_expired_is_zero(self):
        s = iw.Session()
        s.lic_exp = time.time() - 30
        self.assertEqual(s.lic_left(), 0.0)

    def test_lic_left_falls_back_to_ttl(self):
        s = iw.Session(captured_at=time.time() - 10, lic_ttl=120)
        self.assertTrue(105 <= s.lic_left() <= 112)

    def test_mpd_left(self):
        s = iw.Session()
        self.assertEqual(s.mpd_left(), -1.0)
        s.mpd_exp = time.time() + 60
        self.assertTrue(55 <= s.mpd_left() <= 60)


class ScanTests(unittest.TestCase):
    def test_scan_extracts_mpd_licence_and_expiry(self):
        exp = int(time.time()) + 120
        cd = make_jwt({"exp": exp})
        blob = ('{"playbackInfo":{"url":"https://cdn.example/a.mpd?exp=9999999999"},'
                '"licenseUrl":"https://widevine-dash.ezdrm.com/proxy?pX=1'
                '\\u0026CustomData=' + cd + '&origin=iwant"}')
        s = iw.Session()
        self.assertTrue(iw._scan_blob(s, blob, force=True))
        self.assertEqual(s.mpd_url, "https://cdn.example/a.mpd?exp=9999999999")
        self.assertEqual(s.mpd_exp, 9999999999.0)
        self.assertNotIn("\\u0026", s.license_url)
        self.assertEqual(s.lic_exp, float(exp))
        self.assertEqual(s.license_mode, "raw")

    def test_scan_ignores_empty_blob(self):
        s = iw.Session()
        self.assertFalse(iw._scan_blob(s, ""))


class MintResetTests(unittest.TestCase):
    def test_reset_clears_urls_expiry_but_keeps_headers(self):
        s = iw.Session(mpd_url="m", license_url="l", license_custom_data="c",
                       mpd_exp=1.0, lic_exp=2.0, captured_at=3.0,
                       license_headers={"x-a": "b"})
        iw._mint_reset(s)
        self.assertEqual((s.mpd_url, s.license_url, s.license_custom_data), ("", "", ""))
        self.assertEqual((s.mpd_exp, s.lic_exp, s.captured_at), (0.0, 0.0, 0.0))
        self.assertEqual(s.license_headers, {"x-a": "b"})


class PremiumBodyTests(unittest.TestCase):
    def test_cap_premium_sets_flags_and_caps(self):
        base = {"assetId": "a", "playbackCapabilities": {"drm": ["wv"], "resolution": ["hd"]}}
        b = iw._cap_premium(base)
        for k, v in iw.PREMIUM_BODY.items():
            self.assertEqual(b[k], v)
        self.assertEqual(b["playbackCapabilities"]["resolution"], ["uhd"])
        self.assertFalse(b["isFreemium"])
        self.assertTrue(b["isEntitled"])
        self.assertFalse(base["isEntitled"] if "isEntitled" in base else False)

    def test_gql_premium_updates_variables_only(self):
        b = iw._gql_premium({"query": "q", "variables": {"serviceId": "SVOD033",
                                                         "quality": "hd"}})
        self.assertEqual(b["query"], "q")
        self.assertEqual(b["variables"]["serviceId"], iw.PREMIUM_BODY["serviceId"])
        self.assertEqual(b["variables"]["quality"], iw.PREMIUM_BODY["quality"])


class PlanTests(unittest.TestCase):
    def test_active_plan_parses_free_plan(self):
        payload = {"data": {"country": "PH", "subscriptions": [{
            "displayName": "iWant FREE Plan", "serviceId": "SVOD033",
            "isFreemium": True, "isInFreeTrial": True, "status": "Active",
            "entitlements": {"quality": "hd", "ads": True}}]}}
        with mock.patch.object(iw.http, "post", return_value=FakeResponse(json_obj=payload)):
            out, err = iw.active_plan("tok", "uid")
        self.assertEqual(err, "")
        self.assertEqual(out["country"], "PH")
        p = out["plans"][0]
        self.assertTrue(p["freemium"])
        self.assertTrue(p["trial"])
        self.assertEqual(p["quality"], "hd")
        self.assertTrue(p["ads"])

    def test_active_plan_no_token(self):
        out, err = iw.active_plan("", "")
        self.assertEqual(out["plans"], [])
        self.assertEqual(err, "no bearer")


class FreshTests(unittest.TestCase):
    def _sess(self, **kw):
        return iw.Session(api_chain=[step("https://api.iwanttfc.com/entitlement/"
                                          "playback/start/a")], **kw)

    def test_fresh_session_does_not_remint(self):
        s = self._sess(mpd_url="m", license_url="l",
                       lic_exp=time.time() + 120, mpd_exp=time.time() + 120)
        with mock.patch.object(iw, "remint") as rm:
            self.assertTrue(iw.ensure_fresh(s))
        rm.assert_not_called()

    def test_unknown_mpd_exp_is_treated_as_fresh(self):
        s = self._sess(mpd_url="m", license_url="l",
                       lic_exp=time.time() + 120, mpd_exp=0.0)
        with mock.patch.object(iw, "remint") as rm:
            self.assertTrue(iw.ensure_fresh(s))
        rm.assert_not_called()

    def test_expired_licence_remints(self):
        s = self._sess(mpd_url="m", license_url="l", lic_exp=time.time() - 1)
        with mock.patch.object(iw, "remint", return_value=True) as rm:
            self.assertTrue(iw.ensure_fresh(s))
        rm.assert_called_once()

    def test_no_chain_cannot_remint(self):
        s = iw.Session(mpd_url="m", license_url="l", lic_exp=time.time() - 1)
        with mock.patch.object(iw, "remint") as rm:
            self.assertFalse(iw.ensure_fresh(s))
        rm.assert_not_called()


class LicensePostTests(unittest.TestCase):
    def test_200_passes_through(self):
        s = iw.Session(license_url="https://widevine-dash.ezdrm.com/proxy?pX=1",
                       license_mode="raw", lic_exp=time.time() + 120)
        r = FakeResponse(status=200, body=b"licence-bytes",
                         headers={"content-type": "application/octet-stream"})
        with mock.patch.object(iw.http, "request", return_value=r) as req:
            resp, err = iw.license_post(s, b"challenge")
        self.assertIs(resp, r)
        self.assertEqual(err, "")
        self.assertEqual(req.call_count, 1)
        self.assertEqual(req.call_args[0][0], "POST")

    def test_expired_licence_forces_remint(self):
        s = iw.Session(license_url="https://widevine-dash.ezdrm.com/proxy?pX=1",
                       license_mode="raw", lic_exp=time.time() - 10)
        r = FakeResponse(status=200, body=b"ok")
        with mock.patch.object(iw, "ensure_fresh", return_value=True) as ef, \
                mock.patch.object(iw.http, "request", return_value=r):
            resp, err = iw.license_post(s, b"challenge")
        self.assertIsNotNone(resp)
        ef.assert_called_once_with(s, force=True)

    def test_401_retries_once_after_remint(self):
        s = iw.Session(license_url="https://widevine-dash.ezdrm.com/proxy?pX=1",
                       license_mode="raw", lic_exp=time.time() + 120)
        bad = FakeResponse(status=401, body=b"denied")
        good = FakeResponse(status=200, body=b"ok")
        with mock.patch.object(iw, "ensure_fresh", return_value=True) as ef, \
                mock.patch.object(iw.http, "request", side_effect=[bad, good]) as req:
            resp, err = iw.license_post(s, b"challenge")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(err, "")
        self.assertEqual(req.call_count, 2)
        ef.assert_called_once_with(s, force=True)

    def test_no_license_url(self):
        resp, err = iw.license_post(iw.Session(), b"x")
        self.assertIsNone(resp)
        self.assertEqual(err, "no license url")


class HeaderTests(unittest.TestCase):
    def test_clean_is_case_insensitive(self):
        h = {"Host": "x", "X-Keep": "y", "Content-Length": "1"}
        self.assertEqual(iw.clean(h, ("host", "content-length")), {"X-Keep": "y"})


class SessionFileTests(unittest.TestCase):
    def test_save_load_roundtrip_normalises_and_keeps_expiry(self):
        exp = int(time.time()) + 120
        cd = make_jwt({"exp": exp})
        url = ("https://widevine-dash.ezdrm.com/proxy?pX=1"
               "\\u0026CustomData=" + cd + "&origin=iwant")
        with tempfile.TemporaryDirectory() as td:
            old = iw.SD
            iw.SD = Path(td)
            try:
                s = iw.Session(asset_id="asset", license_url=url, lic_exp=float(exp))
                p = iw.save_sess(s)
                self.assertTrue(Path(p).exists())
                t = iw.load_sess(p)
                self.assertNotIn("\\u0026", t.license_url)
                self.assertEqual(t.lic_exp, float(exp))
                self.assertEqual(t.asset_id, "asset")
            finally:
                iw.SD = old

    def test_load_recomputes_missing_expiry(self):
        exp = int(time.time()) + 120
        cd = make_jwt({"exp": exp})
        url = f"https://widevine-dash.ezdrm.com/proxy?pX=1&CustomData={cd}&origin=iwant"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "s.json"
            p.write_text(json.dumps({"schema_version": 21, "asset_id": "a",
                                     "license_url": url, "lic_exp": 0.0}),
                         encoding="utf-8")
            t = iw.load_sess(p)
            self.assertEqual(t.lic_exp, float(exp))


class SelftestWiringTests(unittest.TestCase):
    def test_synthetic_jwt_roundtrip(self):
        tok = iw._synthetic_jwt({"exp": 123, "uid": "u"})
        self.assertEqual(iw.jwt_exp(tok), 123.0)
        self.assertEqual(iw._uid_from_jwt(tok), "u")

    def test_newest_complete_prefers_full_session(self):
        with tempfile.TemporaryDirectory() as td:
            old = iw.SD
            iw.SD = Path(td)
            try:
                (Path(td) / "empty.json").write_text(json.dumps({"asset_id": "x"}),
                                                     encoding="utf-8")
                (Path(td) / "full.json").write_text(
                    json.dumps({"asset_id": "y", "mpd_url": "m", "license_url": "l"}),
                    encoding="utf-8")
                self.assertEqual(iw.newest_complete().name, "full.json")
            finally:
                iw.SD = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
