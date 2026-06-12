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
    QMainWindow, QLabel, QFileDialog, QMessageBox, QTextCursor, QTextCharFormat,
    ALIGN_HCENTER, ORIENT_VERTICAL, FORMAT_RGB888, FONT_BOLD, KEEP_ANCHOR,
    app_exec, BINDING,
)
from check_eu_signatures import (
    SignedPdf, EuTrustedListClient, XmlCache, ValidationContextBuilder,
    QcStatementParser, cert_subject_cn, DEFAULT_LOTL_URL, default_cache_dir,
)

UI_FILE = Path(__file__).with_name("signature_viewer.ui")

ABOUT_TEXT = "PDF qualified signature validation from EU TL CA roots PyQt utility."


# ══════════════════════════════════════════════════════════════════════════════
# Report generation (pure logic — no Qt — so it can run on a worker thread)
# ══════════════════════════════════════════════════════════════════════════════

def build_signature_report(pdf_path: str, *, cache_dir: str = "cache",
                           refresh_cache: bool = False,
                           hard_revocation: bool = False,
                           lotl_url: str = DEFAULT_LOTL_URL,
                           do_validate: bool = True,
                           log_fetch: bool = False,
                           log=lambda msg: None,
                           progress=lambda done, total: None) -> str:
    """
    Produce the plain-text report shown in the lower pane: for each signature,
    its certificate summary, cryptographic validation result, and parsed
    QCStatements.

    log:       progress-message callback (str -> None), shown in the status bar.
    progress:  numeric progress callback (done, total) for a progress bar;
               total == 0 signals an indeterminate/busy phase (e.g. LOTL fetch).
    log_fetch: when True, fetch activity is printed to stdout (and fetch errors
               to stderr) exactly as the command-line tool does.
    """
    qc_parser = QcStatementParser()
    out: list[str] = []

    with SignedPdf(pdf_path) as pdf:
        if not pdf.has_signatures:
            return "No signatures found in this PDF."

        out.append(f"{len(pdf.signatures)} signature(s) found in {Path(pdf_path).name}")
        out.append("")

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
                out.append(f"(trust anchors: {len(certs)} qualified CA certs from EU TLs)")
                log(f"Collected {len(certs)} qualified CA certificate(s).")
            except Exception as e:
                out.append(f"(EU Trusted Lists unavailable: {e} — trust not checked)")
                vc = ValidationContextBuilder().build()  # empty trust store
                log(f"Trusted List download failed: {e}")
        else:
            out.append("(validation skipped: --no-validate)")

        for i, sig in enumerate(pdf.signatures, 1):
            out.append("")
            out.append("═" * 66)
            out.append(f"Signature #{i} — field: {sig.field_name}")
            out.append("═" * 66)

            if sig.error or sig.signer_cert is None:
                out.append(f"  ⚠ Could not extract signer certificate: {sig.error}")
                continue

            sc = sig.signer_cert
            out.append("Signer certificate")
            out.append(f"  Common name : {cert_subject_cn(sc)}")
            out.append(f"  Subject     : {sc.subject.rfc4514_string()}")
            out.append(f"  Issuer      : {sc.issuer.rfc4514_string()}")
            out.append(f"  Serial      : {sc.serial_number:x}")
            out.append(f"  Valid from  : {sc.not_valid_before_utc}")
            out.append(f"  Valid until : {sc.not_valid_after_utc}")
            out.append(f"  Chain certs : {len(sig.chain)}")
            if sig.coverage:
                out.append(f"  Coverage    : {sig.coverage}")

            # Cryptographic validation (run once, reused below)
            v = pdf.validate(sig, vc) if vc is not None else None
            if v is not None:
                out.append("")
                out.append("Validation")
                if v.error:
                    out.append(f"  ⚠ Validation error: {v.error}")
                out.append(f"  Intact (unmodified)         : {v.intact}")
                out.append(f"  CMS signature valid         : {v.valid}")
                out.append(f"  Chains to EU TL trust anchor : {v.trusted}")
                out.append(f"  Revoked                     : {v.revoked}")

            # QCStatements
            qc = qc_parser.parse_signature(sig)
            out.append("")
            out.append("QCStatements (ETSI EN 319 412-5)")
            out.append(f"  Present                       : {qc.has_qc_statements}")
            if qc.has_qc_statements:
                out.append(f"  QcCompliance (is qualified)   : {qc.qc_compliance}")
                out.append(f"  QcSSCD (key in secure device) : {qc.qc_sscd}")
                out.append(f"  QcType esign (natural person) : {qc.qct_esign}")
                out.append(f"  QcType eseal (legal person)   : {qc.qct_eseal}")
                out.append(f"  QcType web authentication     : {qc.qct_web}")
                if qc.statement_ids:
                    out.append(f"  Statement IDs : {', '.join(qc.statement_ids)}")
                if qc.qc_type_oids:
                    out.append(f"  QcType values : {', '.join(qc.qc_type_oids)}")

            # Verdict
            out.append("")
            if v is not None:
                sound = v.valid and v.intact
                fully = sound and v.trusted and not v.revoked
                if fully and qc.is_qualified_natural_person:
                    out.append("  VERDICT: QUALIFIED e-signature — natural person (eIDAS Art. 3(12))")
                elif fully and qc.is_qualified_legal_person:
                    out.append("  VERDICT: QUALIFIED e-seal — legal person (eIDAS Art. 3(27))")
                elif fully:
                    out.append("  VERDICT: Trusted, but cert lacks a qualified-signature QCStatement")
                elif sound:
                    out.append("  VERDICT: Cryptographically valid, but not chaining to an EU TL anchor")
                else:
                    out.append("  VERDICT: Failed cryptographic validation (modified/invalid/revoked)")
            else:
                if qc.is_qualified_natural_person:
                    out.append("  NOTE: cert carries qualified natural-person QCStatements "
                               "(validation skipped)")

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# Background worker so TL download + validation don't freeze the UI
# ══════════════════════════════════════════════════════════════════════════════

class ReportWorker(QThread):
    finished_text = pyqtSignal(str)
    progress = pyqtSignal(str)            # status-bar text
    progress_value = pyqtSignal(int, int)  # (done, total) for the progress bar

    def __init__(self, pdf_path: str, opts: dict):
        super().__init__()
        self.pdf_path = pdf_path
        self.opts = opts

    def run(self) -> None:
        try:
            text = build_signature_report(
                self.pdf_path,
                log=self.progress.emit,
                progress=lambda done, total: self.progress_value.emit(done, total),
                **self.opts,
            )
        except Exception as e:
            text = f"Failed to analyse signatures:\n{e}"
        self.finished_text.emit(text)


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
        uic.loadUi(str(UI_FILE), self)  # creates self.pdfScroll, self.infoText, actions, …

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

        # Accept PDFs dropped anywhere on the window. The read-only info pane
        # would otherwise swallow drops, so opt it out.
        self.setAcceptDrops(True)
        self.infoText.setAcceptDrops(False)

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
        self.infoText.setPlainText(
            "No PDF loaded.\n\n"
            "Open one with File ▸ Open, or drag a PDF file onto this window."
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

    def _show_about(self) -> None:
        QMessageBox.about(self, "About", ABOUT_TEXT)

    # ── analysis lifecycle ─────────────────────────────────────────────────
    def _start_worker(self, opts: dict, busy_text: str) -> None:
        if not self.pdf_path:
            return  # nothing to analyse yet
        self.infoText.setPlainText(busy_text)
        # Show an indeterminate (busy) progress bar until the first update.
        self.progressBar.setRange(0, 0)
        self.progressBar.setVisible(True)
        self._worker = ReportWorker(self.pdf_path, opts)
        self._worker.progress.connect(self.statusBar().showMessage)
        self._worker.progress_value.connect(self._on_progress_value)
        self._worker.finished_text.connect(self._on_report_ready)
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

    def _on_report_ready(self, text: str) -> None:
        self.infoText.setPlainText(text)
        self._bold_verdict_lines()
        self.progressBar.setVisible(False)
        self.statusBar().showMessage("Done", 4000)

    def _bold_verdict_lines(self) -> None:
        """Make any line containing 'VERDICT' bold so it stands out."""
        doc = self.infoText.document()
        fmt = QTextCharFormat()
        fmt.setFontWeight(FONT_BOLD)
        block = doc.firstBlock()
        while block.isValid():
            if "VERDICT" in block.text():
                cursor = QTextCursor(doc)
                cursor.setPosition(block.position())
                cursor.setPosition(block.position() + max(block.length() - 1, 0),
                                   KEEP_ANCHOR)
                cursor.mergeCharFormat(fmt)
            block = block.next()


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
    args = ap.parse_args(argv)

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
