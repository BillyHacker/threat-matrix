"""Global IT Outage & Threat Matrix - Flask backend.
Sources: NVD CVE 2.0 (paged), GitHub Advisory DB, Statuspage /api/v2 endpoints, Mastodon #infosec.
AI: local Ollama (set OLLAMA_MODEL). Falls back to keyword heuristics if Ollama is off."""
import os, re, json, csv, io, time, sqlite3, threading, datetime as dt
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import requests
from flask import Flask, jsonify, render_template, request, Response

OLLAMA = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
NVD_KEY = os.getenv("NVD_API_KEY", "")
GH_TOKEN = os.getenv("GITHUB_TOKEN", "")
REFRESH, LLM_PER_CYCLE = 300, 12
DB = os.getenv("DB_PATH", "monitor.db")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE, NVD_MAX_PAGES = 2000, 3          # up to 6000 CVEs per 24h window
UA = {"User-Agent": "threat-matrix-demo/1.0"}

# hours = window length, n = histogram buckets, step = hours per bucket
RANGES = {
    "1h": dict(hours=1, n=12, step=1 / 12, fmt="%H:%M", label="1H", bl="5 minutes"),
    "24h": dict(hours=24, n=24, step=1, fmt="%H:%M", label="24H", bl="hour"),
    "7d": dict(hours=168, n=28, step=6, fmt="%a %H:%M", label="7D", bl="6 hours"),
}

# name: (statuspage base url, lat, lon) - map pins sit at each company's HQ
SERVICES = {
    "GitHub": ("https://www.githubstatus.com", 37.77, -122.42),
    "Cloudflare": ("https://www.cloudflarestatus.com", 37.78, -122.39),
    "Discord": ("https://discordstatus.com", 37.80, -122.45),
    "Atlassian": ("https://status.atlassian.com", -33.87, 151.21),
    "Twilio": ("https://status.twilio.com", 37.75, -122.40),
    "Datadog": ("https://status.datadoghq.com", 40.75, -73.99),
    "DigitalOcean": ("https://status.digitalocean.com", 40.71, -74.00),
    "Zoom": ("https://status.zoom.us", 37.33, -121.89),
    "Shopify": ("https://www.shopifystatus.com", 45.42, -75.70),
}
CATS = {
    "OS": r"windows|linux|kernel|macos|android|\bios\b|ubuntu",
    "Browser": r"chrome|firefox|safari|edge|browser|webkit",
    "Cloud": r"aws|azure|gcp|kubernetes|docker|cloud|container",
    "Network": r"router|firewall|vpn|cisco|fortinet|palo alto|juniper|dns|tls|ssl",
    "Database": r"sql|mongodb|redis|postgres|oracle|database",
    "Web/App": r"wordpress|php|npm|java|node|django|apache|nginx|plugin|xss|package",
}
app = Flask(__name__)
STATE = {"services": [], "panic": {"panic": 0, "mood": "warming up", "posts": []}, "updated": None, "log": []}


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY, source TEXT, title TEXT,
            severity TEXT, cvss REAL, url TEXT, published TEXT, plain TEXT, impact INTEGER, tags TEXT)""")
        c.execute("CREATE TABLE IF NOT EXISTS snaps(ts TEXT PRIMARY KEY, degraded INTEGER, panic INTEGER, uptime REAL)")
        c.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")


def age_hours(p):
    d = dt.datetime.fromisoformat(p.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - d).total_seconds() / 3600


# ---------- collectors ----------
def parse_nvd(v):
    c, m = v["cve"], v["cve"].get("metrics", {})
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    cvss, sev = None, "UNKNOWN"
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if k in m:
            d = m[k][0]["cvssData"]
            cvss = d.get("baseScore")
            sev = (d.get("baseSeverity") or m[k][0].get("baseSeverity") or "UNKNOWN").upper()
            break
    return dict(id=c["id"], source="NVD", title=c["id"], severity=sev, cvss=cvss,
                url="https://nvd.nist.gov/vuln/detail/" + c["id"], published=c["published"], desc=desc)


def fetch_nvd():
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=1)
    f = "%Y-%m-%dT%H:%M:%S.000"
    h = dict(UA)
    if NVD_KEY:
        h["apiKey"] = NVD_KEY
    out, idx = [], 0
    for _ in range(NVD_MAX_PAGES):
        r = requests.get(NVD_URL, headers=h, timeout=60, params={
            "pubStartDate": start.strftime(f), "pubEndDate": end.strftime(f),
            "resultsPerPage": NVD_PAGE, "startIndex": idx})
        r.raise_for_status()
        j = r.json()
        vulns = j.get("vulnerabilities", [])
        out += [parse_nvd(v) for v in vulns]
        idx += len(vulns)
        if not vulns or idx >= j.get("totalResults", 0):
            break
        time.sleep(0.6 if NVD_KEY else 6.5)   # NVD rate limit between pages
    return out


def fetch_ghsa():
    h = dict(UA, Accept="application/vnd.github+json")
    if GH_TOKEN:
        h["Authorization"] = "Bearer " + GH_TOKEN
    r = requests.get("https://api.github.com/advisories", headers=h, timeout=30,
                     params={"per_page": 100, "type": "reviewed", "sort": "published", "direction": "desc"})
    r.raise_for_status()
    return [dict(id=a["ghsa_id"], source="GitHub", title=a["summary"], severity=(a.get("severity") or "unknown").upper(),
                 cvss=(a.get("cvss") or {}).get("score"), url=a["html_url"], published=a["published_at"],
                 desc=a["summary"] + " " + (a.get("description") or "")[:600]) for a in r.json()]


def _svc(item):
    n, (u, la, lo) = item
    try:
        j = requests.get(u + "/api/v2/summary.json", headers=UA, timeout=10).json()
        comps = j.get("components", [])
        return dict(name=n, lat=la, lon=lo, indicator=j["status"]["indicator"], desc=j["status"]["description"],
                    bad=sum(1 for c in comps if c["status"] != "operational"), total=len(comps))
    except Exception:
        return dict(name=n, lat=la, lon=lo, indicator="unknown", desc="unreachable", bad=0, total=0)


def fetch_services():
    with ThreadPoolExecutor(max_workers=9) as ex:
        return list(ex.map(_svc, SERVICES.items()))


# ---------- AI ----------
def llm(prompt):
    r = requests.post(OLLAMA + "/api/generate", timeout=120,
                      json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"})
    return json.loads(r.json()["response"])


def clean(text, title=""):
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    t = re.sub(r"[#*`>_|]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    if title and t.lower().startswith(title.lower()):
        t = t[len(title):].strip(" -:")
    t = re.sub(r"^(executive summary|summary|description|impact)\s*:?\s*", "", t, flags=re.I)
    return t or title


def heuristic(it):
    t = (it["title"] + " " + it["desc"]).lower()
    tags = [k for k, p in CATS.items() if re.search(p, t)] or ["Other"]
    cv = it["cvss"] or {"CRITICAL": 9, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2}.get(it["severity"], 4)
    d = clean(it["desc"], it["title"])
    plain = d if len(d) <= 170 else d[:170].rsplit(" ", 1)[0] + "..."
    return {"plain": plain, "impact": round(cv), "tags": tags}


def enrich(it, use_llm=True):
    out = heuristic(it)
    if not use_llm:
        return out
    try:
        j = llm('You brief non-technical executives. Return JSON with keys "plain" (ONE plain-English sentence, max 25 words, '
                'what could happen to a business), "impact" (integer 1-10 business impact), "tags" (up to 4 affected '
                'vendors/products). Vulnerability: ' + it["desc"][:1200])
        out = {"plain": str(j.get("plain", out["plain"]))[:220],
               "impact": max(1, min(10, int(j.get("impact", out["impact"])))),
               "tags": [str(t)[:24] for t in j.get("tags", out["tags"])][:4] or out["tags"]}
    except Exception:
        pass
    return out


FEEDS = ["infosec.exchange", "mastodon.social", "fosstodon.org", "mstdn.social"]


def fetch_posts():
    for host in FEEDS:
        try:
            r = requests.get(f"https://{host}/api/v1/timelines/tag/infosec", params={"limit": 20}, headers=UA, timeout=8)
            j = r.json()
            if r.ok and isinstance(j, list) and j:
                return [re.sub(r"<[^>]+>", " ", p["content"]).strip()[:280] for p in j]
            print("feed", host, "returned HTTP", r.status_code)
        except Exception as e:
            print("feed", host, "failed:", e)
    return []


def fetch_panic():
    posts = fetch_posts()
    if not posts:
        raise RuntimeError("no Mastodon feed reachable")
    try:
        j = llm('Rate the overall PANIC level (0-100) of this infosec community chatter. Return JSON '
                '{"panic": int, "mood": "3-word phrase"}.\n' + "\n".join(posts))
        return {"panic": max(0, min(100, int(j["panic"]))), "mood": str(j.get("mood", ""))[:30], "posts": posts[:6]}
    except Exception:
        hits = sum(bool(re.search(r"zero-?day|0day|actively exploited|ransomware|breach|critical|rce", p, re.I)) for p in posts)
        return {"panic": min(100, 10 + hits * 9), "mood": "keyword estimate", "posts": posts[:6]}


# ---------- storage + sync ----------
def store(items):
    with db() as c:
        known = {r[0] for r in c.execute("select id from items")}
        new = sorted((i for i in items if i["id"] not in known), key=lambda i: i["cvss"] or 0, reverse=True)
        for n, i in enumerate(new):
            e = enrich(i, use_llm=n < LLM_PER_CYCLE)
            c.execute("insert or ignore into items values(?,?,?,?,?,?,?,?,?,?)",
                      (i["id"], i["source"], i["title"], i["severity"], i["cvss"], i["url"], i["published"],
                       e["plain"], e["impact"], json.dumps(e["tags"])))
    return len(new)


def note(msg):
    print("[sync]", msg, flush=True)
    STATE["log"] = (STATE["log"] + [msg])[-8:]


def refresh():
    STATE["log"] = []
    now = dt.datetime.now(dt.timezone.utc)
    STATE["services"] = fetch_services()
    down = [s["name"] for s in STATE["services"] if s["indicator"] == "unknown"]
    note(f"status pages {len(STATE['services']) - len(down)}/{len(STATE['services'])} reachable"
         + (f" (unreachable: {', '.join(down)})" if down else ""))
    for f in (fetch_ghsa, fetch_nvd):
        try:
            items = f()
            note(f"{f.__name__[6:].upper()}: {len(items)} fetched, {store(items)} new")
        except Exception as e:
            note(f"{f.__name__[6:].upper()} FAILED: {str(e)[:110]}")
    try:
        STATE["panic"] = fetch_panic()
        note("chatter feed ok")
    except Exception:
        note("no Mastodon feed reachable, panic is an estimate")
        with db() as c:
            tot, crit = c.execute("select count(*), sum(severity in ('CRITICAL','HIGH')) from items").fetchone()
        deg = sum(1 for s in STATE["services"] if s["indicator"] not in ("none", "unknown"))
        STATE["panic"] = {"panic": min(100, 10 + round(40 * (crit or 0) / max(tot, 1)) + 10 * deg),
                          "mood": "estimate: no social feed", "posts": []}
    deg = sum(1 for s in STATE["services"] if s["indicator"] not in ("none", "unknown"))
    comps = sum(s["total"] for s in STATE["services"])
    bad = sum(s["bad"] for s in STATE["services"])
    uptime = round(100 * (comps - bad) / comps, 1) if comps else 0
    with db() as c:
        c.execute("insert or replace into snaps values(?,?,?,?)", (now.isoformat(), deg, STATE["panic"]["panic"], uptime))
        c.execute("delete from snaps where ts < ?", ((now - dt.timedelta(days=8)).isoformat(),))
        c.execute("insert or ignore into meta values('first_sync', ?)", (now.isoformat(),))
    STATE["updated"] = now.isoformat()


def loop():
    while True:
        try:
            refresh()
        except Exception as e:
            print("refresh failed:", e)
        time.sleep(REFRESH)


# ---------- change + baseline ----------
def window_counts(rows, P, pred):
    """Count matching CVEs in the current window and the window before it."""
    cur = prev = 0
    for r in rows:
        if not pred(r):
            continue
        a = age_hours(r["published"])
        if 0 <= a < P:
            cur += 1
        elif P <= a < 2 * P:
            prev += 1
    return cur, prev


def baseline(now, P):
    """A change % is only honest once the database covers the whole prior window.
    The NVD pull reaches 24h before the first sync, so coverage starts there."""
    with db() as c:
        row = c.execute("select v from meta where k='first_sync'").fetchone()
    need = 2 * P
    if not row:
        return dict(ok=False, have=0.0, need=need)
    first = dt.datetime.fromisoformat(row[0])
    have = (now - first).total_seconds() / 3600 + 24
    return dict(ok=have >= need, have=round(have, 1), need=need)


def change(cur, prev, base, label):
    if not base["ok"]:
        return dict(ok=False, cur=cur, prev=prev, pct=0,
                    text=f"BASELINE {base['have']:.0f}H / {base['need']}H")
    pct = (cur - prev) / prev * 100 if prev else (100.0 if cur else 0.0)
    return dict(ok=True, cur=cur, prev=prev, pct=round(pct, 1), text=f"{pct:+.1f}% VS PRIOR {label}")


# ---------- routes ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def data():
    key = request.args.get("range", "24h")
    if key not in RANGES:
        key = "24h"
    R = RANGES[key]
    P, n, step = R["hours"], R["n"], R["step"]
    now = dt.datetime.now(dt.timezone.utc)

    with db() as c:
        rows = [dict(r) for r in c.execute("select * from items order by published desc")]
    for r in rows:
        r["tags"] = json.loads(r["tags"])

    tot_h, crit_h = [0] * n, [0] * n
    inr, cv = [], []
    sev, cats, src = Counter(), Counter(), Counter()
    for r in rows:
        a = age_hours(r["published"])
        if 0 <= a < P:
            inr.append(r)
            idx = n - 1 - min(n - 1, int(a / step))
            tot_h[idx] += 1
            if r["severity"] in ("CRITICAL", "HIGH"):
                crit_h[idx] += 1
    for r in inr:
        sev[r["severity"]] += 1
        src[r["source"]] += 1
        if r["cvss"]:
            cv.append(r["cvss"])
        blob = (r["title"] + " " + r["plain"] + " " + " ".join(r["tags"])).lower()
        for k, p in CATS.items():
            if re.search(p, blob):
                cats[k] += 1

    cur_t, prev_t = window_counts(rows, P, lambda r: True)
    cur_c, prev_c = window_counts(rows, P, lambda r: r["severity"] in ("CRITICAL", "HIGH"))
    base = baseline(now, P)

    labels = [(now - dt.timedelta(hours=(n - 1 - i) * step)).astimezone().strftime(R["fmt"]) for i in range(n)]
    since = (now - dt.timedelta(hours=P)).isoformat()
    with db() as c:
        snaps = [dict(s) for s in c.execute("select degraded, panic, uptime from snaps where ts >= ? order by ts", (since,))]
    if len(snaps) > 60:
        k = len(snaps) / 60
        snaps = [snaps[int(i * k)] for i in range(60)]

    sv = STATE["services"]
    comps = sum(s["total"] for s in sv)
    bad = sum(s["bad"] for s in sv)
    deg_names = [s["name"] for s in sv if s["indicator"] not in ("none", "unknown")]
    kpi = dict(
        total=len(inr), nvd=src["NVD"], gh=src["GitHub"],
        crit=cur_c, c_crit=sev["CRITICAL"], c_high=sev["HIGH"],
        avg_cvss=round(sum(cv) / len(cv), 1) if cv else 0, max_cvss=max(cv) if cv else 0,
        change_total=change(cur_t, prev_t, base, R["label"]),
        change_crit=change(cur_c, prev_c, base, R["label"]),
        degraded=len(deg_names), deg_names=deg_names, nodes=len(sv),
        uptime=round(100 * (comps - bad) / comps, 1) if comps else 0)

    return jsonify(range=key, label=R["label"], bucket_label=R["bl"], labels=labels,
                   hist=tot_h, crit_hist=crit_h,
                   deg_hist=[s["degraded"] for s in snaps], panic_hist=[s["panic"] for s in snaps],
                   items=inr[:60], sev=sev, cats={k: cats.get(k, 0) for k in CATS}, services=sv,
                   panic=STATE["panic"], updated=STATE["updated"], log=STATE["log"], kpi=kpi)


@app.route("/api/detail")
def detail():
    kind = request.args.get("kind", "cves")
    key = request.args.get("range", "24h")
    if key not in RANGES:
        key = "24h"
    P, label = RANGES[key]["hours"], RANGES[key]["label"]

    if kind == "services":
        rows = [dict(s, url=SERVICES[s["name"]][0]) for s in STATE["services"]]
        bad = [s for s in rows if s["indicator"] not in ("none", "unknown")]
        return jsonify(kind=kind, title="Service status", total=len(rows),
                       subtitle=f"{len(bad)} of {len(rows)} services report problems. Open a status page for its incident history.",
                       rows=rows, posts=[], history=[], summary={"operational": len(rows) - len(bad), "degraded": len(bad)})

    if kind == "panic":
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=P)).isoformat()
        with db() as c:
            hist = [r[0] for r in c.execute("select panic from snaps where ts >= ? order by ts", (since,))]
        p = STATE["panic"]
        mood = p.get("mood", "")
        if mood == "warming up":
            source, expl = "none yet", "The first sync has not finished, so there is no score yet."
        elif mood == "estimate: no social feed":
            source = "estimate (no feed)"
            expl = ("No Mastodon server answered, so this score is an estimate built from the share of critical/high CVEs "
                    "and the number of degraded services. It is not a reading of community chatter.")
        elif mood == "keyword estimate":
            source = "keyword fallback"
            expl = "The AI model is not running, so the score counts alarming words in the sampled posts instead."
        else:
            source = "AI model"
            expl = "The AI model read the sampled #infosec posts and rated the overall panic level."
        return jsonify(kind=kind, title="Community panic", total=len(p.get("posts", [])),
                       subtitle=f"Score {p.get('panic', 0)} of 100, source: {source}.",
                       score=p.get("panic", 0), mood=mood, source=source, explanation=expl,
                       posts=p.get("posts", []), history=hist, rows=[], summary={})

    with db() as c:
        rows = [dict(r) for r in c.execute("select * from items order by published desc")]
    inr = []
    for r in rows:
        if 0 <= age_hours(r["published"]) < P:
            r["tags"] = json.loads(r["tags"])
            inr.append(r)
    sev, src, cats = Counter(), Counter(), Counter()
    for r in inr:
        sev[r["severity"]] += 1
        src[r["source"]] += 1
        blob = (r["title"] + " " + r["plain"] + " " + " ".join(r["tags"])).lower()
        for k, pat in CATS.items():
            if re.search(pat, blob):
                cats[k] += 1
    if kind == "crit":
        pick = [r for r in inr if r["severity"] in ("CRITICAL", "HIGH")]
        pick.sort(key=lambda r: r["cvss"] or 0, reverse=True)
        title = "Critical / High"
        subtitle = f"{len(pick)} CVEs rated critical or high in the last {label}, highest CVSS first."
    else:
        pick = inr
        title = "CVEs tracked"
        subtitle = f"{len(inr)} CVEs published in the last {label}, newest first."
    return jsonify(kind=kind, title=title, subtitle=subtitle, total=len(pick), posts=[], history=[],
                   rows=[dict(id=r["id"], source=r["source"], severity=r["severity"], cvss=r["cvss"],
                              published=r["published"], plain=r["plain"], tags=r["tags"], url=r["url"])
                         for r in pick[:200]],
                   summary={"sources": dict(src), "severity": dict(sev),
                            "categories": {k: cats[k] for k in CATS if cats.get(k)}})


@app.route("/export.csv")
def export():
    with db() as c:
        rows = c.execute("select id,source,severity,cvss,impact,published,plain,tags,url from items order by published desc").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "source", "severity", "cvss", "impact", "published", "plain_english", "tags", "url"])
    w.writerows([tuple(r) for r in rows])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=threats.csv"})


_started = False


def start_background():
    """Start the database and sync loop once per process. Runs under gunicorn (Render) and python app.py."""
    global _started
    if _started or os.getenv("DISABLE_SYNC") == "1":
        return
    _started = True
    init()
    threading.Thread(target=loop, daemon=True).start()


start_background()

if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", 5000)), debug=False)
