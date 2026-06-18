#!/usr/bin/env python3
"""
SigViewer web interface
=======================
A single-page Flask app that wraps the Qt-free core: upload a PDF, run
``build_signature_data`` on a background thread, poll progress every 500 ms,
and render the same opaque display tree the PyQt GUI shows.

This module exposes a standard WSGI ``app`` object, so the *same code* runs
under Flask's dev server and under a production server with no changes:

    Development (auto-reload + debugger):   ./flask_run.sh
                                            (or: python webapp.py)
    Production (Linux, behind nginx):       gunicorn -w 1 --threads 8 webapp:app
    Production (cross-platform, no nginx):  waitress-serve --port=8080 webapp:app

NOTE on workers: job state is kept in-process, so run the production server
with a SINGLE worker process and multiple THREADS (``-w 1 --threads N``).
Multiple worker *processes* wouldn't share the job dictionary, so a poll could
hit a worker that never saw the job.
"""

from __future__ import annotations

import os
import time
import uuid
import tempfile
import threading

from flask import (
    Flask, request, jsonify, abort, render_template_string, Response,
)
from werkzeug.utils import secure_filename

from check_eu_signatures import (
    build_signature_data, build_display_tree, default_cache_dir,
)

app = Flask(__name__)
#: Reject uploads larger than this (bytes) — a simple abuse guard.
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

#: Port used by the built-in dev server (override with $PORT).
PORT = int(os.environ.get("PORT", "8080"))

#: How long a finished/abandoned job is retained before pruning (seconds).
JOB_TTL = 600

# In-process job store: job_id -> dict(state, done, total, tree, error, created).
# Guarded by a lock because the dev/prod servers are multi-threaded.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _prune_jobs() -> None:
    """Drop jobs older than ``JOB_TTL`` so the store doesn't grow unbounded."""
    now = time.time()
    with _jobs_lock:
        stale = [jid for jid, j in _jobs.items() if now - j["created"] > JOB_TTL]
        for jid in stale:
            _jobs.pop(jid, None)


def _set(job_id: str, **fields) -> None:
    """Atomically update fields of a job if it still exists."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(fields)


def _run_job(job_id: str, pdf_path: str, opts: dict) -> None:
    """Background worker: analyse the PDF and store the resulting display tree.

    Args:
        job_id: the job's id in ``_jobs``.
        pdf_path: temp file to analyse (deleted when done).
        opts: keyword options for ``build_signature_data``.
    """
    def progress(done: int, total: int) -> None:
        # total == 0 → indeterminate/busy phase (fetching the LOTL).
        _set(job_id, done=done, total=total)

    try:
        data = build_signature_data(pdf_path, progress=progress, **opts)
        _set(job_id, state="done", tree=build_display_tree(data))
    except Exception as e:  # noqa: BLE001 — surface any failure to the client
        _set(job_id, state="error", error=str(e))
    finally:
        try:
            os.unlink(pdf_path)
            os.rmdir(os.path.dirname(pdf_path))
        except OSError:
            pass


@app.get("/")
def index() -> str:
    """Serve the single-page UI."""
    return render_template_string(INDEX_HTML)


@app.post("/analyze")
def analyze():
    """Accept a PDF upload, start a background analysis, return its job id."""
    _prune_jobs()
    f = request.files.get("pdf")
    if f is None or f.filename == "":
        abort(400, "No PDF uploaded.")

    # "validate" checkbox; unchecked → offline parse (no TL download).
    do_validate = request.form.get("validate", "true") != "false"

    # Save under the original (sanitised) basename inside a private temp dir, so
    # the "N signature(s) found in <name>" header shows the real filename.
    safe_name = secure_filename(f.filename) or "upload.pdf"
    if not safe_name.lower().endswith(".pdf"):
        safe_name += ".pdf"
    tmpdir = tempfile.mkdtemp(prefix="sigviewer-")
    path = os.path.join(tmpdir, safe_name)
    f.save(path)

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "state": "running", "done": 0, "total": 0,
            "tree": None, "error": None, "created": time.time(),
        }

    opts = dict(do_validate=do_validate, cache_dir=default_cache_dir())
    threading.Thread(target=_run_job, args=(job_id, path, opts), daemon=True).start()
    return jsonify(job_id=job_id)


@app.get("/status/<job_id>")
def status(job_id: str):
    """Return a job's progress/result. Polled by the page every 500 ms."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            abort(404, "Unknown job.")
        resp = {k: job[k] for k in ("state", "done", "total", "error")}
        if job["state"] == "done":
            resp["tree"] = job["tree"]
    return jsonify(resp)


# ──────────────────────────────────────────────────────────────────────────────
# Single-page UI (HTML + CSS + JS). Styled to echo the PyQt results tree:
# indentation by depth, bold two-line signature/verdict node, alternating rows.
# Labels are injected with innerHTML, which is safe because the core escapes all
# dynamic text and only ever emits <strong>/<em>.
# ──────────────────────────────────────────────────────────────────────────────
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EU Signature Viewer</title>
<style>
  :root { --bg:#f4f6f8; --panel:#ffffff; --line:#d4d9df; --accent:#215aa0;
          --row-alt:#f4f6f8; --text:#1d2530; --muted:#6b7682; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, "Segoe UI", Roboto, sans-serif;
         color:var(--text); background:var(--bg); }
  header { background:var(--panel); border-bottom:1px solid var(--line);
           padding:12px 16px; display:flex; align-items:center; gap:16px;
           flex-wrap:wrap; }
  header h1 { font-size:15px; font-weight:600; margin:0; color:var(--accent); }
  .spacer { flex:1; }
  button.open { background:var(--accent); color:#fff; border:0; border-radius:6px;
                padding:8px 16px; font-size:14px; cursor:pointer; }
  button.open:hover { filter:brightness(1.08); }
  label.chk { font-size:13px; color:var(--muted); display:flex; align-items:center;
              gap:6px; cursor:pointer; }
  main { padding:16px; max-width:1000px; margin:0 auto; }
  .progress-wrap { display:none; margin:8px 0 16px; }
  .progress-wrap.on { display:block; }
  .progress-label { font-size:13px; color:var(--muted); margin-bottom:4px; }
  progress { width:100%; height:16px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px;
           overflow:hidden; }
  .panel-title { font-size:13px; font-weight:600; color:var(--muted);
                 padding:8px 12px; border-bottom:1px solid var(--line);
                 background:#fafbfc; }
  #tree { padding:4px 0; }
  .node { padding:4px 12px; font-size:13.5px; line-height:1.35;
          white-space:pre-line; border-bottom:1px solid #f0f2f4; }
  .node:nth-of-type(even) { background:var(--row-alt); }
  .node.branch { font-weight:500; }
  .node strong { font-weight:700; }
  .empty { color:var(--muted); font-size:14px; padding:24px 12px; text-align:center; }
  .error { color:#b3261e; }
</style>
</head>
<body>
<header>
  <h1>EU Signature Viewer</h1>
  <button class="open" id="openBtn">Open PDF…</button>
  <label class="chk"><input type="checkbox" id="validate" checked>
    Validate against EU Trusted Lists</label>
  <span class="spacer"></span>
  <span class="muted" id="fileName" style="font-size:13px;color:var(--muted)"></span>
  <input type="file" id="fileInput" accept="application/pdf" hidden>
</header>

<main>
  <div class="progress-wrap" id="progressWrap">
    <div class="progress-label" id="progressLabel">Working…</div>
    <progress id="bar"></progress>
  </div>

  <div class="panel">
    <div class="panel-title">Signatures &amp; QCStatements</div>
    <div id="tree"><div class="empty">Open a PDF to validate its signatures.</div></div>
  </div>
</main>

<script>
const openBtn = document.getElementById('openBtn');
const fileInput = document.getElementById('fileInput');
const validate = document.getElementById('validate');
const fileName = document.getElementById('fileName');
const tree = document.getElementById('tree');
const progressWrap = document.getElementById('progressWrap');
const progressLabel = document.getElementById('progressLabel');
const bar = document.getElementById('bar');

let pollTimer = null;

openBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) upload(fileInput.files[0]);
});

function setBusy(label) {
  progressWrap.classList.add('on');
  progressLabel.textContent = label;
  bar.removeAttribute('value');           // indeterminate
}
function setDeterminate(done, total) {
  progressLabel.textContent = `Fetching trust lists… ${done} / ${total}`;
  bar.max = total; bar.value = done;
}
function hideProgress() { progressWrap.classList.remove('on'); }

function upload(file) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  fileName.textContent = file.name;
  tree.innerHTML = '';
  setBusy('Uploading…');

  const fd = new FormData();
  fd.append('pdf', file);
  fd.append('validate', validate.checked ? 'true' : 'false');

  fetch('/analyze', { method: 'POST', body: fd })
    .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(t)))
    .then(({ job_id }) => poll(job_id))
    .catch(err => showError(String(err)));
}

function poll(jobId) {
  setBusy('Working…');
  pollTimer = setInterval(() => {
    fetch('/status/' + jobId)
      .then(r => r.ok ? r.json() : Promise.reject('status ' + r.status))
      .then(s => {
        if (s.state === 'running') {
          if (s.total > 0) setDeterminate(s.done, s.total);
          else setBusy('Working…');
        } else if (s.state === 'done') {
          clearInterval(pollTimer); pollTimer = null;
          hideProgress();
          renderTree(s.tree);
        } else if (s.state === 'error') {
          clearInterval(pollTimer); pollTimer = null;
          hideProgress();
          showError(s.error || 'Analysis failed.');
        }
      })
      .catch(err => { clearInterval(pollTimer); pollTimer = null;
                      hideProgress(); showError(String(err)); });
  }, 500);
}

function showError(msg) {
  tree.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'empty error';
  d.textContent = msg;
  tree.appendChild(d);
}

// Render the opaque display tree. label is server-escaped (only <strong>/<em>),
// so innerHTML is safe. Indentation by depth mirrors the PyQt QTreeView.
function renderTree(nodes) {
  tree.innerHTML = '';
  if (!nodes || !nodes.length) {
    showError('No data.'); return;
  }
  const walk = (list, depth) => {
    for (const n of list) {
      const row = document.createElement('div');
      row.className = 'node' + (n.children ? ' branch' : ' leaf');
      row.style.paddingLeft = (12 + depth * 20) + 'px';
      row.innerHTML = n.label;
      tree.appendChild(row);
      if (n.children) walk(n.children, depth + 1);
    }
  };
  walk(nodes, 0);
}
</script>
</body>
</html>
"""


if __name__ == "__main__":
    # Flask's built-in dev server: threaded so polling and the background job
    # run concurrently; debug enables the reloader + interactive debugger.
    app.run(host="127.0.0.1", port=PORT, debug=True, threaded=True)
