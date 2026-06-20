# Deploying the PDF Validator web app (Ubuntu 22.04 + nginx, no Docker)

Goal: serve the app at `https://your-host/abc123XYZ/PDF_validator/` from the
existing nginx site, with the Python app isolated in a venv and run by gunicorn
under systemd. The app code lives in `/opt/pdf_validator` (kept separate from
`/var/www/html`, which keeps serving your static pages).

> Pick your own random segment instead of `abc123XYZ`:
> `openssl rand -hex 8`

## venv vs system packages — use a venv

Use a **venv with pip**, not apt, for the Python dependencies:
- key deps (`pyhanko`, `pyhanko-certvalidator`) are not in apt at all;
- apt's `pymupdf`/`cryptography` are usually older than what the app was tested
  with;
- Ubuntu 22.04 blocks pip-into-system-Python (PEP 668) and mixing apt+pip is
  fragile;
- the heavy deps ship manylinux wheels, so pip needs no compiler.

So apt is used only for `python3-venv` (and nginx); everything Python comes
from PyPI into the venv.

## 1. System packages (one-time)

```bash
sudo apt update
sudo apt install -y python3-venv   # nginx already present
```

## 2. Lay down the app

Copy ONLY the files the web app needs (no PyQt/GUI files required):

```
webapp.py
check_eu_signatures.py
i18n.py
templates/            (index.html)
static/               (style.css, app.js)
locale/               (with compiled <lang>/LC_MESSAGES/*.mo)
deploy/requirements-web.txt
```

```bash
sudo mkdir -p /opt/pdf_validator
sudo cp -r webapp.py check_eu_signatures.py i18n.py templates static locale \
          deploy/requirements-web.txt /opt/pdf_validator/
sudo chown -R www-data:www-data /opt/pdf_validator
```

Make sure the translation catalogs are COMPILED (`.mo` present). If you only
copied `.po`, either compile locally first (`pybabel compile -d locale -D
sigviewer`) and copy the `.mo`, or install Babel in the venv and compile there.

## 3. Create the venv and install deps

```bash
cd /opt/pdf_validator
sudo -u www-data python3 -m venv venv
sudo -u www-data venv/bin/pip install --upgrade pip
sudo -u www-data venv/bin/pip install -r requirements-web.txt
```

## 4. Writable cache directory

The app caches the EU Trusted Lists (with a cross-process lock) under
`$XDG_CACHE_HOME`, which the service sets to `/var/cache/pdf_validator`:

```bash
sudo mkdir -p /var/cache/pdf_validator
sudo chown www-data:www-data /var/cache/pdf_validator
```

(The server must be allowed outbound HTTPS to `ec.europa.eu` and the national
TL hosts for the first fetch; afterwards it serves from cache.)

## 5. Install and start the service

```bash
sudo cp deploy/pdf_validator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pdf_validator
sudo systemctl status pdf_validator        # should be active (running)
curl -s http://127.0.0.1:8000/ | head -1   # sanity check (served at root locally)
```

## 6. Wire up nginx

Open the existing site config (e.g. `/etc/nginx/sites-available/default`) and
paste the two `location` blocks from `deploy/nginx-pdf_validator.conf` INSIDE
the `server { ... }` block that serves `/var/www/html`. Replace `abc123XYZ`
with your random string (the same one in both files). Then:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Visit `https://your-host/abc123XYZ/PDF_validator/` — the Open PDF button,
progress bar, and results tree should work, with all URLs under the subpath.

## Updating later

```bash
sudo cp webapp.py check_eu_signatures.py i18n.py /opt/pdf_validator/
sudo cp -r templates static locale /opt/pdf_validator/
sudo chown -R www-data:www-data /opt/pdf_validator
sudo systemctl restart pdf_validator
```

## Notes / gotchas

- **Single worker on purpose.** The unit runs `gunicorn --workers 1 --threads
  8`. The job store and the TL cache lock are in-process; multiple worker
  *processes* wouldn't share them. Threads give you concurrency for the polling
  + background analysis, which is plenty for low traffic.
- **Upload size.** `client_max_body_size 50m` in nginx must be ≥
  `MAX_CONTENT_LENGTH` (50 MB) in `webapp.py`, or large PDFs 413 at nginx.
- **Subpath correctness** comes from `X-Forwarded-Prefix` (nginx) +
  `ProxyFix` (app) + `request.script_root` injected into the page; the JS
  prefixes its `fetch()` calls with it. No app code edits needed to change the
  path — just change it in BOTH nginx location blocks (and reload).
- **Pin versions** for reproducibility once it works:
  `sudo -u www-data venv/bin/pip freeze > /opt/pdf_validator/requirements.lock`.
- **Logs:** `journalctl -u pdf_validator -f`.
