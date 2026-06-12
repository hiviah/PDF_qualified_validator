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
import argparse
from pathlib import Path

import fitz  # PyMuPDF

from qt_compat import (
    uic, QThread, pyqtSignal, QImage, QPixmap, QApplication, QMainWindow,
    QLabel, QFileDialog, QMessageBox, ALIGN_HCENTER, ORIENT_VERTICAL,
    FORMAT_RGB888, app_exec, BINDING,
)
from check_eu_signatures import (
    SignedPdf, EuTrustedListClient, XmlCache, ValidationContextBuilder,
    QcStatementParser, cert_subject_cn, DEFAULT_LOTL_URL,
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
                           log=lambda msg: None) -> str:
    """
    Produce the plain-text report shown in the lower pane: for each signature,
    its certificate summary, cryptographic validation result, and parsed
    QCStatements. `log` is an optional progress callback (str -> None).
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
                log("Downloading EU Trusted Lists…")
                cache = XmlCache(cache_dir=cache_dir, force_refresh=refresh_cache,
                                 verbose=False)
                client = EuTrustedListClient(lotl_url=lotl_url, cache=cache, verbose=False)
                certs = client.all_qualified_ca_certs()
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
    progress = pyqtSignal(str)

    def __init__(self, pdf_path: str, opts: dict):
        super().__init__()
        self.pdf_path = pdf_path
        self.opts = opts

    def run(self) -> None:
        try:
            text = build_signature_report(
                self.pdf_path, log=self.progress.emit, **self.opts
            )
        except Exception as e:
            text = f"Failed to analyse signatures:\n{e}"
        self.finished_text.emit(text)


# ══════════════════════════════════════════════════════════════════════════════
# PDF rendering controller (renders pages into the .ui's pdfContents layout)
# ══════════════════════════════════════════════════════════════════════════════

class PdfPageRenderer:
    """Renders PDF pages (via PyMuPDF) as QLabels into a target QVBoxLayout."""

    def __init__(self, pdf_path: str, layout, zoom: float = 1.5):
        self._doc = fitz.open(pdf_path)
        self._layout = layout
        self._zoom = zoom
        self.render()

    def load(self, pdf_path: str) -> None:
        """Open a different PDF and re-render the pages."""
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
    def page_count(self) -> int:
        return self._doc.page_count

    def zoom_in(self) -> None:
        self._zoom = min(self._zoom * 1.25, 6.0)
        self.render()

    def zoom_out(self) -> None:
        self._zoom = max(self._zoom / 1.25, 0.25)
        self.render()


# ══════════════════════════════════════════════════════════════════════════════
# Main window: loads the shared .ui, then wires logic to the widgets
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self, pdf_path: str, opts: dict, autostart: bool = True):
        super().__init__()
        uic.loadUi(str(UI_FILE), self)  # creates self.pdfScroll, self.infoText, actions, …

        self.pdf_path = pdf_path
        self.opts = opts
        self._worker = None  # type: ReportWorker | None

        self.setWindowTitle(f"EU Signature Viewer ({BINDING}) — {Path(pdf_path).name}")

        # PDF rendering into the layout defined in the .ui
        self._renderer = PdfPageRenderer(pdf_path, self.pdfContents.layout())

        # Proportional initial split (runtime-only API, not expressible in .ui)
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

        self.statusBar().showMessage(f"{self._renderer.page_count} page(s) — {BINDING}")

        if autostart:
            self.start_analysis()

    # ── menu handlers ───────────────────────────────────────────────────────
    def _open_pdf(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PDF", str(Path(self.pdf_path).parent),
            "PDF files (*.pdf);;All files (*)",
        )
        if path:
            self.load_pdf(path)

    def load_pdf(self, pdf_path: str) -> None:
        """Switch to a different PDF: re-render pages and re-run analysis."""
        self.pdf_path = pdf_path
        self._renderer.load(pdf_path)
        self.setWindowTitle(f"EU Signature Viewer ({BINDING}) — {Path(pdf_path).name}")
        self.statusBar().showMessage(f"{self._renderer.page_count} page(s) — {BINDING}")
        self.start_analysis()

    def _show_about(self) -> None:
        QMessageBox.about(self, "About", ABOUT_TEXT)

    # ── analysis lifecycle ─────────────────────────────────────────────────
    def _start_worker(self, opts: dict, busy_text: str) -> None:
        self.infoText.setPlainText(busy_text)
        self._worker = ReportWorker(self.pdf_path, opts)
        self._worker.progress.connect(self.statusBar().showMessage)
        self._worker.finished_text.connect(self._on_report_ready)
        self._worker.start()

    def start_analysis(self) -> None:
        self._start_worker(self.opts, "Analysing signatures…")

    def _refresh_lists(self) -> None:
        opts = dict(self.opts, refresh_cache=True)
        self._start_worker(opts, "Refreshing EU Trusted Lists and re-validating…")

    def _on_report_ready(self, text: str) -> None:
        self.infoText.setPlainText(text)
        self.statusBar().showMessage("Done", 4000)


# ══════════════════════════════════════════════════════════════════════════════
# Entry point (shared by both executables)
# ══════════════════════════════════════════════════════════════════════════════

def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description="View a PDF and its EU qualified signatures.")
    ap.add_argument("pdf", help="Path to the PDF file")
    ap.add_argument("--cache", default="cache", metavar="DIR",
                    help="On-disk LOTL/TL XML cache directory (default: ./cache)")
    ap.add_argument("--refresh-cache", action="store_true",
                    help="Force re-download of the Trusted Lists")
    ap.add_argument("--hard-revocation", action="store_true",
                    help="Require and fetch OCSP/CRL revocation info")
    ap.add_argument("--no-validate", action="store_true",
                    help="Skip the Trusted-List download and validation "
                         "(still shows signatures + QCStatements, offline)")
    ap.add_argument("--lotl-url", default=DEFAULT_LOTL_URL, help="Override the LOTL URL")
    args = ap.parse_args(argv)

    if not Path(args.pdf).exists():
        print(f"File not found: {args.pdf}")
        return 1

    opts = dict(
        cache_dir=args.cache,
        refresh_cache=args.refresh_cache,
        hard_revocation=args.hard_revocation,
        do_validate=not args.no_validate,
        lotl_url=args.lotl_url,
    )

    app = QApplication(sys.argv)
    win = MainWindow(args.pdf, opts)
    win.show()
    return app_exec(app)


if __name__ == "__main__":
    raise SystemExit(main())
