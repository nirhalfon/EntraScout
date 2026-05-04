#!/usr/bin/env python3
"""blobweb — local Flask UI for anonymous Azure Blob exploration.

Run:
    cd /Users/osher/EntraScout && source .venv/bin/activate
    pip install flask  # if missing
    python tools/blobweb.py
    # then open http://127.0.0.1:5050

Read-only — only anonymous GETs, no auth, no writes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET

try:
    from flask import Flask, render_template_string, request, abort, send_file, Response
except ImportError:
    print("ERROR: flask not installed. Run:\n  pip install flask", file=sys.stderr)
    sys.exit(2)

import httpx

# ---------------- Reuse blobexplorer logic ----------------
THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(THIS_DIR))
import blobexplorer as bx  # type: ignore


app = Flask(__name__)
client = httpx.Client(
    headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
    follow_redirects=True,
    timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
    http2=False,
)


PAGE = """
<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Blob Explorer</title>
<style>
  body { font: 14px/1.45 -apple-system, system-ui, sans-serif; margin: 24px; background:#0d1117; color:#c9d1d9; }
  h1 { color:#58a6ff; margin: 0 0 16px 0; }
  form { margin-bottom: 24px; padding: 14px; background:#161b22; border-radius:6px; border:1px solid #30363d; }
  label { display:inline-block; min-width: 110px; color:#8b949e; }
  input[type=text] { background:#0d1117; color:#c9d1d9; border:1px solid #30363d; padding:6px 8px; border-radius:4px; width: 320px; }
  input[type=submit] { background:#238636; color:#fff; border:none; padding:8px 14px; border-radius:4px; cursor:pointer; font-weight:600; }
  input[type=submit]:hover { background:#2ea043; }
  input[type=submit].secondary { background:#30363d; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th, td { padding:6px 8px; text-align:left; border-bottom:1px solid #30363d; font-size:13px; }
  th { background:#161b22; color:#8b949e; }
  tr.sensitive { background:rgba(248,81,73,0.07); }
  .flag { color:#f85149; font-weight:700; }
  .ok { color:#3fb950; }
  .muted { color:#6e7681; }
  pre { background:#161b22; padding:12px; border-radius:6px; border:1px solid #30363d; overflow:auto; }
  a { color:#58a6ff; text-decoration:none; }
  a:hover { text-decoration:underline; }
  .row { display:flex; gap:18px; margin-bottom:8px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:10px; background:#21262d; font-size:11px; color:#8b949e; margin-right:6px; }
  .pill.open { background:#1f6feb; color:#fff; }
  .pill.deny { background:#30363d; color:#8b949e; }
  .stat { display:inline-block; margin-right:18px; }
  .stat b { color:#58a6ff; }
  details { margin-top:8px; }
  summary { cursor:pointer; color:#58a6ff; }
  .btn { display:inline-block; padding:2px 6px; margin-right:4px; border:1px solid #30363d; border-radius:4px; background:#21262d; color:#58a6ff; text-decoration:none; font-size:13px; }
  .btn:hover { background:#30363d; text-decoration:none; }
</style>
</head>
<body>
<h1>🗂  Blob Explorer <span class="muted" style="font-size:13px">— anonymous Azure Blob recon</span></h1>

<form method="get" action="/">
  <div class="row"><label>Account / URL:</label>
    <input name="account" type="text" value="{{account or ''}}" placeholder="dhsfiles  or  https://acct.blob.core.windows.net" required autofocus>
  </div>
  <div class="row"><label>Container:</label>
    <input name="container" type="text" value="{{container or ''}}" placeholder="(blank = probe well-known)">
  </div>
  <div class="row"><label>Filter (regex):</label>
    <input name="grep" type="text" value="{{grep or ''}}" placeholder='\\.pdf$  |  password|secret|export'>
  </div>
  <div class="row"><label>Brand to verify:</label>
    <input name="attribute" type="text" value="{{attribute or ''}}" placeholder="dhs.gov  (optional — runs attribution check)">
  </div>
  <div class="row"><label></label>
    <input type="submit" value="Explore">
    <label style="margin-left:14px"><input type="checkbox" name="sensitive" {% if sensitive %}checked{% endif %}> sensitive only</label>
  </div>
</form>

{% if error %}<pre style="color:#f85149">{{error}}</pre>{% endif %}

{% if probe_results %}
  <h2>Container probe — {{account}}</h2>
  <p>
    {% for c, status, hasblob in probe_results %}
      {% if status == 200 %}
        <a class="pill open" href="/?account={{account}}&container={{c}}">{{c}}{% if hasblob %} ✓{% endif %}</a>
      {% else %}
        <span class="pill deny">{{c}} ({{status}})</span>
      {% endif %}
    {% endfor %}
  </p>
{% endif %}

{% if attribution %}
  <h2>Attribution: {{account}} ↔ {{attribute}}</h2>
  <p>Score: <b style="color: {{ '#3fb950' if attribution.score >= 0.4 else '#d29922' }};">{{ '%.2f'|format(attribution.score) }}</b>
     {% if attribution.score >= 0.7 %}— confident{% elif attribution.score >= 0.4 %}— likely{% else %}— inconclusive{% endif %}</p>
  <ul>{% for r in attribution.reasons %}<li>{{r}}</li>{% endfor %}</ul>
{% endif %}

{% if blobs is not none %}
  <h2>{{account}} / {{container}} — {{ blobs|length }} blobs</h2>
  <div>
    <span class="stat">total: <b>{{ stats.total }}</b></span>
    <span class="stat">sensitive: <b style="color:#f85149">{{ stats.sensitive }}</b></span>
    <span class="stat">size shown: <b>{{ stats.size_h }}</b></span>
  </div>
  <table>
    <tr><th>flag</th><th>name</th><th>size</th><th>last modified</th><th>type</th><th>actions</th></tr>
    {% for b in blobs %}
      <tr class="{{ 'sensitive' if b.sensitive else '' }}">
        <td>{% if b.sensitive %}<span class="flag">!</span>{% endif %}</td>
        <td style="font-family:monospace;font-size:12px">{{b.name}}</td>
        <td>{{b.size_h}}</td>
        <td class="muted">{{b.last_modified[:25]}}</td>
        <td class="muted">{{b.content_type}}</td>
        <td>
          <a class="btn" href="/download?u={{b.url|urlencode}}" title="download">⬇</a>
          <a class="btn" href="/preview?u={{b.url|urlencode}}" title="preview">👁</a>
          <a class="btn" href="{{b.url}}" target="_blank" title="open in new tab">↗</a>
        </td>
      </tr>
    {% endfor %}
  </table>
  {% if not blobs %}<p class="muted">empty / not listable / filtered out</p>{% endif %}
{% endif %}

{% if preview %}
  <h2>Preview — {{ preview.url }}</h2>
  <p class="muted">HTTP {{preview.status}} · content-length {{preview.size_h}} · type {{preview.content_type}}</p>
  <details open><summary>Headers</summary>
    <pre>{% for k,v in preview.headers %}{{k}}: {{v}}
{% endfor %}</pre></details>
  <details open><summary>First 2 KB</summary>
    <pre>{{ preview.body }}</pre></details>
{% endif %}

<p class="muted" style="margin-top:32px;font-size:12px">Read-only · anonymous GETs only · for authorized recon.</p>
</body></html>
"""


def humansize(n: int) -> str:
    f = float(n)
    for u in ["B", "KB", "MB", "GB"]:
        if f < 1024:
            return f"{f:.1f}{u}"
        f /= 1024
    return f"{f:.1f}TB"


@app.route("/")
def index():
    account = (request.args.get("account") or "").strip()
    container = (request.args.get("container") or "").strip()
    grep = (request.args.get("grep") or "").strip()
    sensitive = bool(request.args.get("sensitive"))
    attribute = (request.args.get("attribute") or "").strip()

    ctx = dict(
        account=account, container=container, grep=grep, sensitive=sensitive,
        attribute=attribute, error=None, probe_results=None,
        attribution=None, blobs=None, stats=None, preview=None,
    )

    if not account:
        return render_template_string(PAGE, **ctx)

    # Attribution mode
    if attribute:
        score = 0.0
        reasons = []
        brand_root = attribute.split(".")[0].lower()
        if brand_root in account.lower():
            score += 0.3
            reasons.append(f"account name contains '{brand_root}' (+0.3)")
        try:
            hits = bx.probe_containers(client, account, bx.WELL_KNOWN_CONTAINERS)
        except Exception as e:
            ctx["error"] = f"probe failed: {e}"
            return render_template_string(PAGE, **ctx)
        open_c = [c for c, s, _ in hits if s == 200]
        sample = 0
        for c in open_c[:3]:
            blobs = bx.list_blobs(client, account, c, max_n=20)
            for b in blobs[:5]:
                if brand_root in b["name"].lower():
                    score += 0.05
                    reasons.append(f"blob name '{b['name']}' contains '{brand_root}'")
                try:
                    r = client.get(b["url"], headers={"Range": "bytes=0-2047"}, timeout=10)
                    txt = r.content.decode("utf-8", errors="replace").lower()
                    if attribute.lower() in txt or brand_root in txt:
                        score += 0.1
                        reasons.append(f"content of '{b['name']}' references '{attribute}'")
                        sample += 1
                except Exception:
                    pass
                if sample > 5:
                    break
            if sample > 5:
                break
        ctx["attribution"] = {"score": score, "reasons": reasons}
        ctx["probe_results"] = hits
        return render_template_string(PAGE, **ctx)

    # Probe mode (no container given)
    if not container:
        try:
            hits = bx.probe_containers(client, account, bx.WELL_KNOWN_CONTAINERS)
        except Exception as e:
            ctx["error"] = f"probe failed: {e}"
            return render_template_string(PAGE, **ctx)
        ctx["probe_results"] = hits
        return render_template_string(PAGE, **ctx)

    # List mode
    try:
        blobs_raw = bx.list_blobs(client, account, container)
    except Exception as e:
        ctx["error"] = f"list failed: {e}"
        return render_template_string(PAGE, **ctx)

    pat = None
    if grep:
        try:
            pat = re.compile(grep)
        except re.error as e:
            ctx["error"] = f"bad regex: {e}"
            return render_template_string(PAGE, **ctx)

    out = []
    total = 0
    sensitive_count = 0
    size_shown = 0
    for b in blobs_raw:
        total += 1
        sens, why = bx.is_sensitive(b["name"])
        if sens:
            sensitive_count += 1
        if pat and not pat.search(b["name"]):
            continue
        if sensitive and not sens:
            continue
        size_shown += b["size"]
        out.append({
            "name": b["name"],
            "size": b["size"],
            "size_h": humansize(b["size"]),
            "last_modified": b["last_modified"],
            "content_type": b["content_type"],
            "url": b["url"],
            "sensitive": sens,
            "why": why,
        })
    ctx["blobs"] = out
    ctx["stats"] = {"total": total, "sensitive": sensitive_count, "size_h": humansize(size_shown)}
    return render_template_string(PAGE, **ctx)


@app.route("/download")
def download():
    url = request.args.get("u")
    if not url or not url.startswith("https://") or ".blob.core.windows.net/" not in url:
        abort(400)
    fname = url.rsplit("/", 1)[-1] or "blob.bin"
    # Probe headers first so we can set Content-Type / Length / fail fast
    try:
        head_r = client.get(url, headers={"Range": "bytes=0-0"}, timeout=20)
    except httpx.HTTPError as e:
        return f"download probe failed: {e}", 502
    if head_r.status_code not in (200, 206):
        return f"upstream HTTP {head_r.status_code}", 502
    ctype = head_r.headers.get("content-type", "application/octet-stream")
    clen = head_r.headers.get("content-range", "").split("/")[-1] or head_r.headers.get("content-length", "")

    def gen():
        # Fresh client inside the generator so its lifecycle matches the response
        with httpx.Client(
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
            timeout=httpx.Timeout(connect=10.0, read=300.0, write=10.0, pool=10.0),
            http2=False,
        ) as c:
            with c.stream("GET", url) as r:
                for chunk in r.iter_bytes(chunk_size=65536):
                    yield chunk

    headers = {"Content-Disposition": f'attachment; filename="{fname}"'}
    if clen and clen.isdigit():
        headers["Content-Length"] = clen
    return Response(gen(), mimetype=ctype, headers=headers)


@app.route("/preview")
def preview():
    url = request.args.get("u")
    if not url or not url.startswith("https://") or ".blob.core.windows.net/" not in url:
        abort(400)
    try:
        r = client.get(url, headers={"Range": "bytes=0-2047"}, timeout=15)
    except httpx.HTTPError as e:
        return render_template_string(PAGE, error=f"preview failed: {e}", account="", container="", grep="", sensitive=False, attribute="", probe_results=None, attribution=None, blobs=None, stats=None, preview=None)
    body = r.content.decode("utf-8", errors="replace")[:4096]
    headers = list(r.headers.items())
    size_h = humansize(int(r.headers.get("content-length", "0") or 0) or len(r.content))
    return render_template_string(
        PAGE,
        account="", container="", grep="", sensitive=False, attribute="",
        error=None, probe_results=None, attribution=None, blobs=None, stats=None,
        preview={
            "url": url, "status": r.status_code, "headers": headers,
            "body": body, "size_h": size_h,
            "content_type": r.headers.get("content-type", ""),
        },
    )


if __name__ == "__main__":
    print("[*] blobweb — http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False)
