#!/usr/bin/env python3
"""
Qt viewer for EU qualified PDF signatures  (PyQt5 / Python 3.10)
===============================================================
A window split into two dockable panes:

    ┌────────────────────────────────┐
    │  PDF  (rendered pages)          │   ← top dock
    ├────────────────────────────────┤   ← draggable splitter
    │  Signatures & QCStatements      │   ← bottom dock (read-only)
    └────────────────────────────────┘

Both panes are QDockWidgets, so they can be resized via the splitter, floated
out of the window, or re-docked. The signature/QCStatement report is generated
by the same classes used on the command line (SignedPdf, EuTrustedListClient,
ValidationContextBuilder, QcStatementParser), with the Trusted-List download +
cryptographic validation run on a background thread so the UI stays responsive.

Note: pyhanko logs path-building failures to stderr for untrusted signatures.
Those logs are intentionally left visible for now (useful while debugging).

Usage:
    python qt_signature_viewer.py <path-to-pdf> [--cache DIR] [--refresh-cache]
                                  [--hard-revocation] [--no-validate]

Requirements (in addition to the checker's deps):
    pip install PyQt5 pymupdf
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path

import fitz  # PyMuPDF
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QImage, QPixmap, QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QDockWidget, QWidget, QVBoxLayout, QLabel,
    QScrollArea, QPlainTextEdit, QToolBar, QStatusBar, QAction,
)

from check_eu_signatures7 import (
    SignedPdf, EuTrustedListClient, XmlCache, ValidationContextBuilder,
    QcStatementParser, cert_subject_cn, DEFAULT_LOTL_URL,
)


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
        tl_note = ""
        if do_validate:
            try:
                log("Downloading EU Trusted Lists…")
                cache = XmlCache(cache_dir=cache_dir, force_refresh=refresh_cache,
                                 verbose=False)
                client = EuTrustedListClient(lotl_url=lotl_url, cache=cache, verbose=False)
                certs = client.all_qualified_ca_certs()
                vc = (ValidationContextBuilder(allow_revocation_fetch=hard_revocation)
                      .add_certs(certs).build())
                tl_note = f"(trust anchors: {len(certs)} qualified CA certs from EU TLs)"
                log(f"Collected {len(certs)} qualified CA certificate(s).")
            except Exception as e:
                tl_note = f"(EU Trusted Lists unavailable: {e} — trust not checked)"
                vc = ValidationContextBuilder().build()  # empty trust store
                log(f"Trusted List download failed: {e}")
        else:
            tl_note = "(validation skipped: --no-validate)"

        out.append(tl_note)

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
                # No validation; still note whether the cert *looks* qualified
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
# PDF rendering pane (PyMuPDF → QImage → scrollable column of pages)
# ══════════════════════════════════════════════════════════════════════════════

class PdfView(QScrollArea):
    def __init__(self, pdf_path: str, zoom: float = 1.5):
        super().__init__()
        self._doc = fitz.open(pdf_path)
        self._zoom = zoom
        self._container = QWidget()
        self._vbox = QVBoxLayout(self._container)
        self._vbox.setSpacing(12)
        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self._render()

    def _clear(self) -> None:
        while self._vbox.count():
            item = self._vbox.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _render(self) -> None:
        self._clear()
        mat = fitz.Matrix(self._zoom, self._zoom)
        for page in self._doc:
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = QImage(pix.samples, pix.width, pix.height, pix.stride,
                         QImage.Format_RGB888).copy()
            lbl = QLabel()
            lbl.setPixmap(QPixmap.fromImage(img))
            lbl.setAlignment(Qt.AlignHCenter)
            self._vbox.addWidget(lbl)
        self._vbox.addStretch(1)

    @property
    def page_count(self) -> int:
        return self._doc.page_count

    def zoom_in(self) -> None:
        self._zoom = min(self._zoom * 1.25, 6.0)
        self._render()

    def zoom_out(self) -> None:
        self._zoom = max(self._zoom / 1.25, 0.25)
        self._render()


# ══════════════════════════════════════════════════════════════════════════════
# Main window: two dock widgets (PDF top, info bottom)
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self, pdf_path: str, opts: dict, autostart: bool = True):
        super().__init__()
        self.pdf_path = pdf_path
        self.opts = opts
        self._worker = None  # type: ReportWorker | None

        self.setWindowTitle(f"EU Signature Viewer — {Path(pdf_path).name}")
        self.resize(960, 1040)
        self.setDockNestingEnabled(True)

        # ── PDF pane (top dock) ──────────────────────────────────────────────
        self.pdf_view = PdfView(pdf_path)
        self.pdf_dock = QDockWidget("PDF", self)
        self.pdf_dock.setObjectName("pdf_dock")
        self.pdf_dock.setWidget(self.pdf_view)

        # ── Signature info pane (bottom dock, read-only) ─────────────────────
        self.info = QPlainTextEdit()
        self.info.setReadOnly(True)
        self.info.setLineWrapMode(QPlainTextEdit.NoWrap)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.info.setFont(mono)
        self.info.setPlainText("Analysing signatures…")
        self.info_dock = QDockWidget("Signatures & QCStatements", self)
        self.info_dock.setObjectName("info_dock")
        self.info_dock.setWidget(self.info)

        # No central widget — let the two docks fill the window and split
        # vertically with a draggable handle between them.
        placeholder = QWidget()
        placeholder.setMaximumHeight(0)
        self.setCentralWidget(placeholder)
        self.addDockWidget(Qt.TopDockWidgetArea, self.pdf_dock)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.info_dock)
        # Give the PDF roughly twice the height of the info pane initially.
        self.resizeDocks([self.pdf_dock, self.info_dock], [680, 340], Qt.Vertical)

        self._build_toolbar()
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(f"{self.pdf_view.page_count} page(s)")

        if autostart:
            self.start_analysis()

    # ── toolbar ──────────────────────────────────────────────────────────────
    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        self.addToolBar(tb)

        act_in = QAction("Zoom +", self)
        act_in.triggered.connect(self.pdf_view.zoom_in)
        tb.addAction(act_in)

        act_out = QAction("Zoom −", self)
        act_out.triggered.connect(self.pdf_view.zoom_out)
        tb.addAction(act_out)

        tb.addSeparator()

        act_refresh = QAction("Refresh trust lists", self)
        act_refresh.triggered.connect(self._refresh_lists)
        tb.addAction(act_refresh)

        tb.addSeparator()
        tb.addAction(self.pdf_dock.toggleViewAction())
        tb.addAction(self.info_dock.toggleViewAction())

    # ── analysis lifecycle ─────────────────────────────────────────────────
    def start_analysis(self) -> None:
        self.info.setPlainText("Analysing signatures…")
        self._worker = ReportWorker(self.pdf_path, self.opts)
        self._worker.progress.connect(self.statusBar().showMessage)
        self._worker.finished_text.connect(self._on_report_ready)
        self._worker.start()

    def _on_report_ready(self, text: str) -> None:
        self.info.setPlainText(text)
        self.statusBar().showMessage("Done", 4000)

    def _refresh_lists(self) -> None:
        # Force a fresh download of LOTL + TLs on the next analysis pass.
        opts = dict(self.opts)
        opts["refresh_cache"] = True
        self._worker = ReportWorker(self.pdf_path, opts)
        self._worker.progress.connect(self.statusBar().showMessage)
        self._worker.finished_text.connect(self._on_report_ready)
        self.info.setPlainText("Refreshing EU Trusted Lists and re-validating…")
        self._worker.start()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
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
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
