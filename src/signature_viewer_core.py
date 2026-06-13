#!/usr/bin/env python3
"""
EU qualified PDF signature viewer — shared logic (binding-agnostic)
==================================================================
All UI layout lives in `signature_viewer.ui` (one file, shared by both the
PyQt5 and PyQt6 executables). All Qt binding differences are isolated in
`qt_compat`. This module contains only logic: PDF page rendering, the
Trusted-List download + cryptographic validation (on a background thread), and
signal/slot wiring.

Don't run this module directly to pick a binding — use the thin executables
`viewer_pyqt5.py` or `viewer_pyqt6.py`. (Running this directly works too and
auto-detects the binding via qt_compat.)
"""

from __future__ import annotations

import sys
import json
import base64
import argparse
from pathlib import Path

import fitz  # PyMuPDF

from qt_compat import (
    uic, QThread, pyqtSignal, QByteArray, QImage, QPixmap, QApplication,
    QMainWindow, QLabel, QFileDialog, QMessageBox, QStandardItemModel,
    QStandardItem, ALIGN_HCENTER, ORIENT_VERTICAL, FORMAT_RGB888,
    app_exec, BINDING,
)
from check_eu_signatures import (
    SignedPdf, EuTrustedListClient, XmlCache, ValidationContextBuilder,
    QcStatementParser, cert_subject_cn, DEFAULT_LOTL_URL, default_cache_dir,
)
from i18n import _, install_language

UI_FILE = Path(__file__).with_name("signature_viewer.ui")

ABOUT_TEXT = "PDF qualified signature validation from EU TL CA roots PyQt utility."


# ══════════════════════════════════════════════════════════════════════════════
# Report generation (pure logic — no Qt — so it can run on a worker thread)
# ══════════════════════════════════════════════════════════════════════════════

def build_signature_data(pdf_path: str, *, cache_dir: str = "cache",
                         refresh_cache: bool = False,
                         hard_revocation: bool = False,
                         lotl_url: str = DEFAULT_LOTL_URL,
                         do_validate: bool = True,
                         log_fetch: bool = False,
                         log=lambda msg: None,
                         progress=lambda done, total: None) -> dict:
    """
    Produce structured data for the results tree:

        {
          "message": str | None,         # set instead of signatures (e.g. "no signatures")
          "header":  str | None,         # "N signature(s) found in foo.pdf"
          "trust_note": str | None,      # trust-anchor summary
          "signatures": [
            {
              "title":   "Signature #1",
              "field":   "Signature1",
              "verdict": "QUALIFIED e-signature — natural person …",
              "error":   str | None,
              "groups":  [ {"name": "Signer certificate",
                            "rows": [("Common name", "Jan Novak"), …]}, … ],
            }, …
          ],
        }

    log:       progress-message callback (str -> None), shown in the status bar.
    progress:  numeric progress callback (done, total); total == 0 => busy phase.
    log_fetch: when True, fetch activity prints to stdout (errors to stderr).
    """
    qc_parser = QcStatementParser()
    result = {"message": None, "header": None, "trust_note": None, "signatures": []}

    with SignedPdf(pdf_path) as pdf:
        if not pdf.has_signatures:
            result["message"] = _("No signatures found in this PDF.")
            return result

        result["header"] = _("%(count)d signature(s) found in %(name)s") % {
            "count": len(pdf.signatures), "name": Path(pdf_path).name}

        # Optionally build the trust anchor set from the EU Trusted Lists.
        vc = None
        if do_validate:
            try:
                progress(0, 0)  # indeterminate: fetching LOTL
                log("Downloading EU Trusted Lists…")
                cache = XmlCache(cache_dir=cache_dir, force_refresh=refresh_cache,
                                 verbose=log_fetch)
                client = EuTrustedListClient(lotl_url=lotl_url, cache=cache,
                                             verbose=log_fetch)

                def _tl_progress(done, total, country):
                    progress(done, total)
                    log(f"Trusted Lists: {done}/{total} ({country})")

                certs = client.all_qualified_ca_certs(progress=_tl_progress)
                vc = (ValidationContextBuilder(allow_revocation_fetch=hard_revocation)
                      .add_certs(certs).build())
                result["trust_note"] = _("Trust anchors: %(count)d qualified CA certs from EU TLs") % {
                    "count": len(certs)}
                log(f"Collected {len(certs)} qualified CA certificate(s).")
            except Exception as e:
                result["trust_note"] = f"EU Trusted Lists unavailable: {e} — trust not checked"
                vc = ValidationContextBuilder().build()  # empty trust store
                log(f"Trusted List download failed: {e}")
        else:
            result["trust_note"] = "Validation skipped (--no-validate)"

        for i, sig in enumerate(pdf.signatures, 1):
            entry = {"title": f"Signature #{i}", "field": sig.field_name,
                     "verdict": "", "error": None, "groups": []}

            if sig.error or sig.signer_cert is None:
                entry["verdict"] = _("Could not extract signer certificate")
                entry["error"] = sig.error
                result["signatures"].append(entry)
                continue

            sc = sig.signer_cert
            signer_rows = [
                ("Common name", cert_subject_cn(sc)),
                ("Subject", sc.subject.rfc4514_string()),
                ("Issuer", sc.issuer.rfc4514_string()),
                ("Serial", f"{sc.serial_number:x}"),
                ("Valid from", str(sc.not_valid_before_utc)),
                ("Valid until", str(sc.not_valid_after_utc)),
                ("Chain certs", str(len(sig.chain))),
            ]
            if sig.coverage:
                signer_rows.append(("Coverage", sig.coverage))
            entry["groups"].append({"name": "Signer certificate", "rows": signer_rows})

            # Cryptographic validation (run once, reused for the verdict)
            v = pdf.validate(sig, vc) if vc is not None else None
            if v is not None:
                val_rows = []
                if v.error:
                    val_rows.append(("Validation error", v.error))
                val_rows += [
                    ("Intact (unmodified)", str(v.intact)),
                    ("CMS signature valid", str(v.valid)),
                    ("Chains to EU TL trust anchor", str(v.trusted)),
                    ("Revoked", str(v.revoked)),
                ]
                entry["groups"].append({"name": "Validation", "rows": val_rows})

            qc = qc_parser.parse_signature(sig)
            qc_rows = [("Present", str(qc.has_qc_statements))]
            if qc.has_qc_statements:
                qc_rows += [
                    ("QcCompliance (is qualified)", str(qc.qc_compliance)),
                    ("QcSSCD (key in secure device)", str(qc.qc_sscd)),
                    ("QcType esign (natural person)", str(qc.qct_esign)),
                    ("QcType eseal (legal person)", str(qc.qct_eseal)),
                    ("QcType web authentication", str(qc.qct_web)),
                ]
                if qc.statement_ids:
                    qc_rows.append(("Statement IDs", ", ".join(qc.statement_ids)))
                if qc.qc_type_oids:
                    qc_rows.append(("QcType values", ", ".join(qc.qc_type_oids)))
            entry["groups"].append({"name": "QCStatements (ETSI EN 319 412-5)", "rows": qc_rows})

            # Verdict
            if v is not None:
                sound = v.valid and v.intact
                fully = sound and v.trusted and not v.revoked
                if fully and qc.is_qualified_natural_person:
                    entry["verdict"] = _("QUALIFIED e-signature — natural person (eIDAS Art. 3(12))")
                elif fully and qc.is_qualified_legal_person:
                    entry["verdict"] = _("QUALIFIED e-seal — legal person (eIDAS Art. 3(27))")
                elif fully:
                    entry["verdict"] = _("Trusted, but cert lacks a qualified-signature QCStatement")
                elif sound:
                    entry["verdict"] = _("Cryptographically valid, but not chaining to an EU TL anchor")
                else:
                    entry["verdict"] = _("Failed cryptographic validation (modified/invalid/revoked)")
            else:
                entry["verdict"] = (
                    _("Cert carries qualified natural-person QCStatements (validation skipped)")
                    if qc.is_qualified_natural_person else _("Validation skipped")
                )

            result["signatures"].append(entry)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Background worker so TL download + validation don't freeze the UI
# ══════════════════════════════════════════════════════════════════════════════

class ReportWorker(QThread):
    finished_data = pyqtSignal(object)     # structured dict for the results tree
    progress = pyqtSignal(str)            # status-bar text
    progress_value = pyqtSignal(int, int)  # (done, total) for the progress bar

    def __init__(self, pdf_path: str, opts: dict):
        super().__init__()
        self.pdf_path = pdf_path
        self.opts = opts

    def run(self) -> None:
        try:
            data = build_signature_data(
                self.pdf_path,
                log=self.progress.emit,
                progress=lambda done, total: self.progress_value.emit(done, total),
                **self.opts,
            )
        except Exception as e:
            data = {"message": f"Failed to analyse signatures:\n{e}",
                    "header": None, "trust_note": None, "signatures": []}
        self.finished_data.emit(data)


# ══════════════════════════════════════════════════════════════════════════════
# PDF rendering controller (renders pages into the .ui's pdfContents layout)
# ══════════════════════════════════════════════════════════════════════════════

class PdfPageRenderer:
    """Renders PDF pages (via PyMuPDF) as QLabels into a target QVBoxLayout."""

    def __init__(self, layout, zoom: float = 1.5):
        self._doc = None
        self._layout = layout
        self._zoom = zoom
        self.show_placeholder()

    def show_placeholder(self) -> None:
        """Empty state shown before any PDF is opened."""
        self._clear()
        lbl = QLabel("Open a PDF — File ▸ Open, or drag a PDF onto the window")
        lbl.setAlignment(ALIGN_HCENTER)
        lbl.setStyleSheet("color: gray; padding: 40px;")
        self._layout.addWidget(lbl)
        self._layout.addStretch(1)

    def load(self, pdf_path: str) -> None:
        """Open a PDF and re-render the pages."""
        if self._doc is not None:
            try:
                self._doc.close()
            except Exception:
                pass
        self._doc = fitz.open(pdf_path)
        self.render()

    def _clear(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def render(self) -> None:
        self._clear()
        mat = fitz.Matrix(self._zoom, self._zoom)
        for page in self._doc:
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = QImage(pix.samples, pix.width, pix.height, pix.stride,
                         FORMAT_RGB888).copy()
            lbl = QLabel()
            lbl.setPixmap(QPixmap.fromImage(img))
            lbl.setAlignment(ALIGN_HCENTER)
            self._layout.addWidget(lbl)
        self._layout.addStretch(1)

    @property
    def has_doc(self) -> bool:
        return self._doc is not None

    @property
    def page_count(self) -> int:
        return self._doc.page_count if self._doc is not None else 0

    def zoom_in(self) -> None:
        if self._doc is None:
            return
        self._zoom = min(self._zoom * 1.25, 6.0)
        self.render()

    def zoom_out(self) -> None:
        if self._doc is None:
            return
        self._zoom = max(self._zoom / 1.25, 0.25)
        self.render()


# ══════════════════════════════════════════════════════════════════════════════
# Main window: loads the shared .ui, then wires logic to the widgets
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self, pdf_path: "str | None" = None, opts: "dict | None" = None,
                 autostart: bool = True, reset_layout: bool = False):
        super().__init__()
        uic.loadUi(str(UI_FILE), self)  # creates self.pdfScroll, self.infoTree, actions, …

        self.pdf_path = None  # set by load_pdf()
        self.opts = opts or {}
        self._worker = None  # type: ReportWorker | None

        # Persisted UI state (dock layout, window geometry, last-open dir) lives
        # in the cache directory so it survives restarts.
        cache_dir = self.opts.get("cache_dir") or default_cache_dir()
        self._ui_state_path = Path(cache_dir) / "ui_state.json"
        self._last_open_dir = ""
        self._recent_files: list[str] = []   # most-recent first, max 5

        # PDF renderer starts empty (placeholder); a document is loaded on demand.
        self._renderer = PdfPageRenderer(self.pdfContents.layout())

        # Default split proportion (used unless a saved layout overrides it).
        self.resizeDocks([self.pdfDock, self.infoDock], [680, 340], ORIENT_VERTICAL)

        # Wire the actions declared in the .ui to logic
        self.actionZoomIn.triggered.connect(self._renderer.zoom_in)
        self.actionZoomOut.triggered.connect(self._renderer.zoom_out)
        self.actionRefresh.triggered.connect(self._refresh_lists)
        # Menu actions
        self.actionOpen.triggered.connect(self._open_pdf)
        self.actionQuit.triggered.connect(self.close)
        self.actionAbout.triggered.connect(self._show_about)

        # Dock show/hide toggles are runtime actions → append them to the toolbar
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.pdfDock.toggleViewAction())
        self.mainToolBar.addAction(self.infoDock.toggleViewAction())

        # Results tree configuration (model is set per-analysis).
        self.infoTree.setHeaderHidden(True)

        # Apply translations to the menu labels (install_language() ran at
        # startup; the .ui ships English source text).
        self._retranslate()

        # Accept PDFs dropped anywhere on the window. The results tree would
        # otherwise swallow drops, so opt it out.
        self.setAcceptDrops(True)
        self.infoTree.setAcceptDrops(False)

        # Restore (or reset) saved geometry + dock layout. Must come after all
        # docks/toolbars exist so restoreState() can match them by objectName.
        if reset_layout:
            self._reset_ui_state()
        else:
            self._restore_ui_state()
        self._rebuild_recent_menu()

        if pdf_path:
            self.load_pdf(pdf_path, analyze=autostart)
        else:
            self._set_no_pdf_state()

    # ── persisted UI state ──────────────────────────────────────────────────
    def _load_ui_state_dict(self) -> dict:
        try:
            return json.loads(self._ui_state_path.read_text())
        except Exception:
            return {}

    def _save_ui_state(self) -> None:
        data = {
            "geometry": base64.b64encode(bytes(self.saveGeometry())).decode(),
            "state": base64.b64encode(bytes(self.saveState())).decode(),
            "last_open_dir": self._last_open_dir,
            "recent_files": self._recent_files,
        }
        try:
            self._ui_state_path.parent.mkdir(parents=True, exist_ok=True)
            self._ui_state_path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass  # never let a cache-write failure break the app

    def _restore_ui_state(self) -> None:
        d = self._load_ui_state_dict()
        self._last_open_dir = d.get("last_open_dir", "") or ""
        self._recent_files = [p for p in (d.get("recent_files") or []) if isinstance(p, str)][:5]
        try:
            if d.get("geometry"):
                self.restoreGeometry(QByteArray(base64.b64decode(d["geometry"])))
            if d.get("state"):
                self.restoreState(QByteArray(base64.b64decode(d["state"])))
        except Exception:
            pass

    def _reset_ui_state(self) -> None:
        # Keep the remembered open-dir and recent files (they aren't layout),
        # but drop the saved geometry/layout so the window uses .ui defaults.
        d = self._load_ui_state_dict()
        self._last_open_dir = d.get("last_open_dir", "") or ""
        self._recent_files = [p for p in (d.get("recent_files") or []) if isinstance(p, str)][:5]
        try:
            self._ui_state_path.unlink()
        except Exception:
            pass

    # ── recent files ────────────────────────────────────────────────────────
    def _add_recent(self, path: str) -> None:
        ap = str(Path(path).expanduser().resolve())
        self._recent_files = [p for p in self._recent_files if p != ap]
        self._recent_files.insert(0, ap)
        del self._recent_files[5:]          # keep at most 5
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self) -> None:
        menu = self.menuOpenRecent
        menu.clear()
        if not self._recent_files:
            menu.setEnabled(False)          # greyed-out when there's nothing
            return
        menu.setEnabled(True)
        for i, path in enumerate(self._recent_files, 1):
            # "&1  /full/path.pdf" — the digit is an Alt-accelerator.
            act = menu.addAction(f"&{i}  {path}")
            act.setData(path)
            act.triggered.connect(lambda checked=False, p=path: self._open_recent(p))

    def _open_recent(self, path: str) -> None:
        if not Path(path).exists():
            self.statusBar().showMessage(f"File no longer exists: {path}", 5000)
            self._recent_files = [p for p in self._recent_files if p != path]
            self._rebuild_recent_menu()
            self._save_ui_state()
            return
        self.load_pdf(path)

    def closeEvent(self, event) -> None:
        self._save_ui_state()
        super().closeEvent(event)

    # ── empty state ─────────────────────────────────────────────────────────
    def _set_no_pdf_state(self) -> None:
        self.pdf_path = None
        self._renderer.show_placeholder()
        self.setWindowTitle(f"EU Signature Viewer ({BINDING})")
        self._show_tree_message(
            "No PDF loaded — open one with File ▸ Open, or drag a PDF onto this window."
        )
        self.statusBar().showMessage(f"No PDF — {BINDING}")

    # ── drag & drop ─────────────────────────────────────────────────────────
    @staticmethod
    def _first_pdf_path(mime) -> "str | None":
        if mime is None or not mime.hasUrls():
            return None
        for url in mime.urls():
            local = url.toLocalFile()
            if local and local.lower().endswith(".pdf"):
                return local
        return None

    def dragEnterEvent(self, event) -> None:
        if self._first_pdf_path(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if self._first_pdf_path(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        path = self._first_pdf_path(event.mimeData())
        if path:
            event.acceptProposedAction()
            self.load_pdf(path)
        else:
            event.ignore()

    # ── menu handlers ───────────────────────────────────────────────────────
    def _open_pdf(self) -> None:
        start_dir = self._last_open_dir or (
            str(Path(self.pdf_path).parent) if self.pdf_path else "")
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PDF", start_dir, "PDF files (*.pdf);;All files (*)",
        )
        if path:
            # Remember the directory File ▸ Open last used.
            self._last_open_dir = str(Path(path).parent)
            self.load_pdf(path)   # records recent + persists state

    def load_pdf(self, pdf_path: str, analyze: bool = True) -> None:
        """Load a PDF: render its pages and (optionally) run signature analysis."""
        self.pdf_path = pdf_path
        self._renderer.load(pdf_path)
        self.setWindowTitle(f"EU Signature Viewer ({BINDING}) — {Path(pdf_path).name}")
        self.statusBar().showMessage(f"{self._renderer.page_count} page(s) — {BINDING}")
        self._add_recent(pdf_path)   # update the Open Recent list
        self._save_ui_state()        # persist recents (+ last dir + geometry)
        if analyze:
            self.start_analysis()

    def _retranslate(self) -> None:
        """Apply the active language to menu labels (English source in the .ui)."""
        self.menuFile.setTitle(_("File"))
        self.menuHelp.setTitle(_("Help"))
        self.menuOpenRecent.setTitle(_("Open Recent"))
        self.actionOpen.setText(_("Open…"))
        self.actionQuit.setText(_("Quit"))
        self.actionAbout.setText(_("About"))
        # Toolbar actions
        self.actionZoomIn.setText(_("Zoom +"))
        self.actionZoomOut.setText(_("Zoom −"))
        self.actionRefresh.setText(_("Refresh trust lists"))
        # Dock title (also drives its toolbar toggle-button label)
        self.infoDock.setWindowTitle(_("Signatures & QCStatements"))

    def _show_about(self) -> None:
        QMessageBox.about(
            self, _("About"),
            _("PDF qualified signature validation from EU TL CA roots PyQt utility."),
        )

    # ── analysis lifecycle ─────────────────────────────────────────────────
    def _start_worker(self, opts: dict, busy_text: str) -> None:
        if not self.pdf_path:
            return  # nothing to analyse yet
        self._show_tree_message(busy_text)
        # Show an indeterminate (busy) progress bar until the first update.
        self.progressBar.setRange(0, 0)
        self.progressBar.setVisible(True)
        self._worker = ReportWorker(self.pdf_path, opts)
        self._worker.progress.connect(self.statusBar().showMessage)
        self._worker.progress_value.connect(self._on_progress_value)
        self._worker.finished_data.connect(self._on_report_ready)
        self._worker.start()

    def _on_progress_value(self, done: int, total: int) -> None:
        if total <= 0:
            # Indeterminate phase (e.g. fetching the LOTL) → busy animation.
            self.progressBar.setRange(0, 0)
        else:
            self.progressBar.setRange(0, total)
            self.progressBar.setValue(done)
        self.progressBar.setVisible(True)

    def start_analysis(self) -> None:
        self._start_worker(self.opts, "Analysing signatures…")

    def _refresh_lists(self) -> None:
        if not self.pdf_path:
            self.statusBar().showMessage("Open a PDF first", 3000)
            return
        opts = dict(self.opts, refresh_cache=True)
        self._start_worker(opts, "Refreshing EU Trusted Lists and re-validating…")

    def _on_report_ready(self, data: dict) -> None:
        self._populate_tree(data)
        self.progressBar.setVisible(False)
        self.statusBar().showMessage("Done", 4000)

    # ── results tree ────────────────────────────────────────────────────────
    @staticmethod
    def _leaf(text: str) -> "QStandardItem":
        item = QStandardItem(text)
        item.setEditable(False)
        return item

    def _show_tree_message(self, text: str) -> None:
        """Show a single informational line in the tree (busy / empty / errors)."""
        model = QStandardItemModel()
        model.invisibleRootItem().appendRow(self._leaf(text))
        self.infoTree.setModel(model)

    def _populate_tree(self, data: dict) -> None:
        model = QStandardItemModel()
        root = model.invisibleRootItem()

        if data.get("message"):
            root.appendRow(self._leaf(data["message"]))
        if data.get("header"):
            root.appendRow(self._leaf(data["header"]))
        if data.get("trust_note"):
            root.appendRow(self._leaf(data["trust_note"]))

        for sig in data.get("signatures", []):
            # Top-level node: "Signature #N" + newline + verdict, in bold.
            top = QStandardItem(f"{sig['title']}\n{sig['verdict']}")
            top.setEditable(False)
            font = top.font()
            font.setBold(True)
            top.setFont(font)

            if sig.get("field"):
                top.appendRow(self._leaf(f"Field: {sig['field']}"))
            if sig.get("error"):
                top.appendRow(self._leaf(f"Error: {sig['error']}"))

            for group in sig.get("groups", []):
                gnode = self._leaf(group["name"])
                for key, value in group["rows"]:
                    gnode.appendRow(self._leaf(f"{key}: {value}"))
                top.appendRow(gnode)

            root.appendRow(top)

        self.infoTree.setModel(model)
        self.infoTree.expandAll()
        self.infoTree.resizeColumnToContents(0)


# ══════════════════════════════════════════════════════════════════════════════
# Entry point (shared by both executables)
# ══════════════════════════════════════════════════════════════════════════════

def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description="View a PDF and its EU qualified signatures.")
    ap.add_argument("pdf", nargs="?", default=None,
                    help="Optional path to a PDF. If omitted, the window opens "
                         "empty — use File ▸ Open or drag a PDF onto it.")
    ap.add_argument("--cache", default=default_cache_dir(), metavar="DIR",
                    help="On-disk LOTL/TL XML cache directory "
                         "(default: $XDG_CACHE_HOME/sigviewer)")
    ap.add_argument("--refresh-cache", action="store_true",
                    help="Force re-download of the Trusted Lists")
    ap.add_argument("--hard-revocation", action="store_true",
                    help="Require and fetch OCSP/CRL revocation info")
    ap.add_argument("--no-validate", action="store_true",
                    help="Skip the Trusted-List download and validation "
                         "(still shows signatures + QCStatements, offline)")
    ap.add_argument("--log-fetch", action="store_true",
                    help="Print how the LOTL and TL XMLs are fetched to stdout "
                         "(and fetch errors to stderr), like the CLI tool does")
    ap.add_argument("--reset-layout", action="store_true",
                    help="Reset the window layout to default, discarding the "
                         "saved dock arrangement and geometry")
    ap.add_argument("--lotl-url", default=DEFAULT_LOTL_URL, help="Override the LOTL URL")
    ap.add_argument("--lang", default=None, metavar="CODE",
                    help="UI language code, e.g. 'cs' (default: $LANG, English fallback)")
    args = ap.parse_args(argv)

    # Activate translations BEFORE building the window or running analysis, so
    # menu labels and verdicts come out in the chosen language.
    install_language(args.lang)

    if args.pdf and not Path(args.pdf).exists():
        print(f"File not found: {args.pdf}")
        return 1

    opts = dict(
        cache_dir=args.cache,
        refresh_cache=args.refresh_cache,
        hard_revocation=args.hard_revocation,
        do_validate=not args.no_validate,
        log_fetch=args.log_fetch,
        lotl_url=args.lotl_url,
    )

    app = QApplication(sys.argv)
    win = MainWindow(args.pdf, opts, reset_layout=args.reset_layout)
    win.show()
    return app_exec(app)


if __name__ == "__main__":
    raise SystemExit(main())
