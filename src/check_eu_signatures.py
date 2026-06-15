#!/usr/bin/env python3
"""
EU Qualified PDF Signature Checker (class-based)
================================================
For each signature in a PDF:
  1. Extract the signer's certificate and chain          (SignedPdf)
  2. Download the EU LOTL + national Trusted Lists and
     collect qualified-CA certificates                    (EuTrustedListClient)
  3. Build a trust anchor set from those certs            (ValidationContextBuilder)
  4. Cryptographically validate each signature against
     that trust anchor set                                (SignedPdf.validate)
  5. Parse QCStatements to see if the signer cert is a
     qualified natural-person e-signature                 (QcStatementParser)

Usage:
    python check_eu_signatures.py <path-to-pdf> [--hard-revocation]

Requirements:
    pip install pyhanko pyhanko-certvalidator lxml requests cryptography asn1crypto
"""

from __future__ import annotations

import sys
import os
import tempfile
import base64
import logging
import argparse
import time
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Iterable

import requests
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ══════════════════════════════════════════════════════════════════════════════
# Constants (OIDs, namespaces, TL service identifiers)
# ══════════════════════════════════════════════════════════════════════════════

# id-etsi-ext-qcStatements  (RFC 3739 / ETSI EN 319 412-5)
OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"
# id-etsi-qcs-QcType: the QCStatement whose statementInfo is a SEQUENCE OF the
# QcType OIDs below. The esign/eseal/web OIDs are *values inside* that sequence,
# NOT statement IDs in their own right.
OID_QC_TYPE = "0.4.0.1862.1.6"
# QcType values (ETSI EN 319 412-5 §4.2.3) — found inside the QcType sequence
OID_QCT_ESIGN = "0.4.0.1862.1.6.1"   # Natural person e-signature
OID_QCT_ESEAL = "0.4.0.1862.1.6.2"   # Legal person e-seal
OID_QCT_WEB   = "0.4.0.1862.1.6.3"   # Website authentication
# QcCompliance – the cert is qualified (statementId, no statementInfo)
OID_QC_COMPLIANCE = "0.4.0.1862.1.1"
# QcSSCD – private key is in an SSCD / QSCD (statementId, no statementInfo)
OID_QC_SSCD = "0.4.0.1862.1.4"

# EU LOTL (List of Trusted Lists) – the master entry point
DEFAULT_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"


def default_cache_dir() -> str:
    """Return the per-user cache directory, following each OS's convention.

    The tool must work when launched from a read-only mount (e.g. an AppImage)
    or from a directory the user can't write to, so it always resolves to a
    writable per-user location:

      * Windows: ``%LOCALAPPDATA%`` (falls back to ``%TEMP%`` / the system temp
        dir) — the standard non-roaming per-user cache location.
      * macOS:   ``~/Library/Caches``.
      * Linux/Unix: ``$XDG_CACHE_HOME`` or ``~/.cache`` (XDG Base Directory).

    Returns:
        The ``sigviewer`` cache directory path for the current platform.
    """
    if os.name == "nt":  # Windows
        base = (os.environ.get("LOCALAPPDATA")
                or os.environ.get("TEMP")
                or tempfile.gettempdir())
    elif sys.platform == "darwin":  # macOS
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:  # Linux / other Unix — XDG Base Directory spec
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
            os.path.expanduser("~"), ".cache")
    return os.path.join(base, "sigviewer")

# ETSI TS 119 612 namespaces
_NS = "{http://uri.etsi.org/02231/v2#}"
_TSLX = "{http://uri.etsi.org/02231/v2/additionaltypes#}"
_TSL_XML_MIME = "application/vnd.etsi.tsl+xml"

# A service that issues qualified certificates
QUALIFIED_CA_SVCTYPE = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
# Service statuses that count as active
GRANTED_STATUSES = {
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
}


def _cert_fingerprint(cert: x509.Certificate) -> str:
    """Return the lowercase hex SHA-256 fingerprint of a certificate.

    Args:
        cert: a cryptography ``x509.Certificate``.
    Returns:
        The SHA-256 digest of the certificate's DER encoding, as hex.
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_subject_cn(cert: x509.Certificate) -> str:
    """Return the Common Name (CN) from a certificate's subject.

    Args:
        cert: a cryptography ``x509.Certificate``.
    Returns:
        The first CN attribute value, or the full RFC4514 subject string
        when the subject has no CN.
    """
    try:
        return cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
    except Exception:
        return cert.subject.rfc4514_string()


# ══════════════════════════════════════════════════════════════════════════════
# Value objects
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SignatureInfo:
    """One embedded PDF signature plus its extracted certificate material.

    Attributes:
        field_name: name of the signature form field.
        signer_cert: the signer's certificate (None if it couldn't be read).
        chain: the certificates supplied with the signature, signer-first.
        coverage: how much of the document the signature covers, if known.
        error: a message set when extraction failed for this signature.
        _embedded: the underlying pyHanko object, kept so ``validate()`` can
            re-run validation on this signature.
    """
    field_name: str
    signer_cert: Optional[x509.Certificate] = None
    chain: list[x509.Certificate] = field(default_factory=list)
    coverage: Optional[str] = None
    error: Optional[str] = None
    # Kept so SignedPdf.validate() can re-run validation on this signature.
    _embedded: object = None


@dataclass
class ValidationResult:
    """Outcome of cryptographically validating one signature.

    Attributes:
        valid: the CMS signature verifies over the signed bytes.
        intact: the document is unmodified within the signature's coverage.
        trusted: a path builds and verifies to a configured trust anchor.
        revoked: True/False if revocation was checked, else None.
        coverage: textual description of the signature's byte coverage.
        bottom_line: pyHanko's overall pass/fail verdict.
        summary: a short human-readable status string.
        error: a message set when validation raised, else None.
    """
    valid: bool = False        # CMS signature verifies over the signed bytes
    intact: bool = False       # document unmodified within signature coverage
    trusted: bool = False      # a path builds+verifies to a trust anchor
    revoked: Optional[bool] = None
    coverage: Optional[str] = None
    bottom_line: bool = False  # pyhanko's overall pass/fail
    summary: str = ""
    error: Optional[str] = None

    @property
    def cryptographically_sound(self) -> bool:
        """Signature verifies and the document was not modified."""
        return self.valid and self.intact


@dataclass
class QcInfo:
    """Parsed id-etsi-ext-qcStatements content for a certificate.

    Attributes:
        has_qc_statements: the QCStatements extension is present.
        qc_compliance: the QcCompliance statement (EU-qualified certificate).
        qc_sscd: the private key resides in a secure signature-creation device.
        qct_esign: QcType esign — natural-person electronic signature.
        qct_eseal: QcType eseal — legal-person electronic seal.
        qct_web: QcType web — website authentication.
        statement_ids: the top-level QCStatement OIDs found.
        qc_type_oids: the OIDs found inside the QcType sequence.
    """
    has_qc_statements: bool = False
    qc_compliance: bool = False
    qc_sscd: bool = False
    qct_esign: bool = False        # natural person
    qct_eseal: bool = False        # legal person / seal
    qct_web: bool = False          # website authentication
    statement_ids: list[str] = field(default_factory=list)   # top-level statement OIDs
    qc_type_oids: list[str] = field(default_factory=list)     # OIDs inside the QcType seq

    @property
    def is_qualified_natural_person(self) -> bool:
        """Whether the certificate denotes a qualified electronic signature for a
        natural person (QcCompliance present together with the esign QcType).
        """
        return self.qc_compliance and self.qct_esign

    @property
    def is_qualified_legal_person(self) -> bool:
        """Whether the certificate denotes a qualified electronic seal for a legal
        person (QcCompliance present together with the eseal QcType).
        """
        return self.qc_compliance and self.qct_eseal


# ══════════════════════════════════════════════════════════════════════════════
# 1. PDF: extract signatures + validate them
# ══════════════════════════════════════════════════════════════════════════════

class SignedPdf:
    """
    Works with a single PDF: extracts embedded signatures and validates them.

    pyhanko's validation re-reads document bytes, so the underlying file must
    stay open for the lifetime of any SignatureInfo you intend to validate.
    Use as a context manager:

        with SignedPdf("doc.pdf") as pdf:
            for sig in pdf.signatures:
                result = pdf.validate(sig, validation_context)

    Attributes:
        path: filesystem path to the PDF being inspected.
        _fh: the open binary file handle (None until ``open()``).
        _reader: the pyHanko ``PdfFileReader`` (None until ``open()``).
        _signatures: cached list of extracted ``SignatureInfo`` (None until
            the ``signatures`` property is first accessed).
    """

    def __init__(self, path: str):
        """Args:
            path: filesystem path to the PDF to inspect.
        """
        self.path = path
        self._fh = None
        self._reader = None
        self._signatures: Optional[list[SignatureInfo]] = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def open(self) -> "SignedPdf":
        """Open the underlying pyHanko PDF reader.

        Called automatically by the context manager.

        Returns:
            self, for convenience.
        """
        from pyhanko.pdf_utils.reader import PdfFileReader
        if self._fh is None:
            self._fh = open(self.path, "rb")
            self._reader = PdfFileReader(self._fh)
        return self

    def close(self) -> None:
        """Release the underlying file handle, if open."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None
            self._reader = None

    def __enter__(self) -> "SignedPdf":
        """Enter the context manager, opening the PDF. Returns self."""
        return self.open()

    def __exit__(self, *exc) -> None:
        """Exit the context manager, closing the PDF.

        Args:
            *exc: the (type, value, traceback) triple (ignored).
        """
        self.close()

    # ── extraction ───────────────────────────────────────────────────────────
    @staticmethod
    def _to_crypto(asn1_cert) -> x509.Certificate:
        """Convert an asn1crypto certificate to a cryptography certificate."""
        return x509.load_der_x509_certificate(asn1_cert.dump(), default_backend())

    def _extract(self) -> list[SignatureInfo]:
        """Parse the embedded signatures into ``SignatureInfo`` records.

        The result is cached on first access.
        """
        if self._reader is None:
            raise RuntimeError("SignedPdf is not open; call open() or use a 'with' block.")

        sigs: list[SignatureInfo] = []
        for emb in self._reader.embedded_signatures:
            info = SignatureInfo(field_name=emb.field_name, _embedded=emb)
            try:
                signer = self._to_crypto(emb.signer_cert)
                chain = [signer]
                seen = {_cert_fingerprint(signer)}
                for c in (emb.other_embedded_certs or []):
                    try:
                        cc = self._to_crypto(c)
                        fp = _cert_fingerprint(cc)
                        if fp not in seen:
                            seen.add(fp)
                            chain.append(cc)
                    except Exception:
                        pass

                info.signer_cert = signer
                info.chain = chain
                try:
                    info.coverage = str(emb.evaluate_signature_coverage())
                except Exception:
                    pass
            except Exception as e:
                info.error = str(e)

            sigs.append(info)
        return sigs

    @property
    def signatures(self) -> list[SignatureInfo]:
        """Embedded signatures, extracted lazily and cached."""
        if self._signatures is None:
            self._signatures = self._extract()
        return self._signatures

    @property
    def has_signatures(self) -> bool:
        """True if the PDF contains at least one embedded signature."""
        return len(self.signatures) > 0

    # ── validation ───────────────────────────────────────────────────────────
    def validate(self, sig: SignatureInfo, validation_context) -> ValidationResult:
        """
        Cryptographically validate one signature against the given pyhanko
        ValidationContext (whose trust roots define what 'trusted' means).
        """
        from pyhanko.sign.validation import validate_pdf_signature

        result = ValidationResult()
        if sig._embedded is None:
            result.error = "No embedded signature object available to validate."
            return result
        try:
            st = validate_pdf_signature(sig._embedded, validation_context)
            result.valid = bool(st.valid)
            result.intact = bool(st.intact)
            result.trusted = bool(st.trusted)
            result.revoked = bool(st.revoked)
            result.coverage = str(st.coverage)
            result.bottom_line = bool(st.bottom_line)
            summary = getattr(st, "summary", None)
            result.summary = summary() if callable(summary) else str(summary)
        except Exception as e:
            result.error = str(e)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# 2. EU Trusted Lists: download + cache LOTL, national TLs, qualified CA certs
# ══════════════════════════════════════════════════════════════════════════════

def _parse_xsd_datetime(text: str) -> Optional[datetime]:
    """Parse an xsd:dateTime (e.g. '2025-06-30T00:00:00Z') as an aware datetime."""
    if not text:
        return None
    s = text.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class XmlCache:
    """
    Persistent on-disk cache for the LOTL and national Trusted List XML.

    Layout under the cache directory:
        cache/LOTL.xml          ← the EU List of Trusted Lists
        cache/AT/TL.xml         ← Austria's national Trusted List
        cache/BE/TL.xml         ← Belgium's, etc. (second level = ISO code)

    Invalidation (a stored file is re-downloaded when):
      * --refresh-cache was given (force_refresh), OR
      * the file is missing, OR
      * its mtime is older than `max_age_hours` (default 24h), OR
      * (LOTL only) the document's own SchemeInformation/NextUpdate is in the
        past — i.e. now > NextUpdate.

    NextUpdate is checked for the LOTL (which the Commission republishes well
    before expiry, so this is reliable) but NOT for national lists, where a
    member state that is late to republish could otherwise force a re-download
    on every run. The 24h mtime rule bounds national freshness instead.

    A successful download is written to disk and also memoised in memory, so a
    single run fetches each URL at most once. If a re-download fails but a stale
    copy exists on disk, the stale copy is used (with a warning) rather than
    failing outright.

    Attributes:
        cache_dir: root directory of the on-disk cache (``Path``).
        max_age_seconds: freshness window in seconds (``max_age_hours`` × 3600).
        force_refresh: when True, every fetch ignores the cached copy.
        session: the ``requests.Session`` used for downloads.
        timeout: per-request timeout in seconds.
        verbose: when True, fetch/cache activity is printed.
        _mem: in-run memo mapping cache path → parsed lxml root.
    """

    def __init__(self, cache_dir: str = "cache", max_age_hours: float = 24.0,
                 force_refresh: bool = False,
                 session: Optional[requests.Session] = None,
                 timeout: int = 30, verbose: bool = True):
        """Args:
            cache_dir: directory holding the cached LOTL/TL XML files.
            max_age_hours: age after which a cached file is considered stale.
            force_refresh: when True, always re-download and ignore cached copies.
            session: optional ``requests.Session`` (one is created if omitted).
            timeout: per-request timeout in seconds.
            verbose: when True, print fetch/cache activity (errors to stderr).
        """
        self.cache_dir = Path(cache_dir)
        self.max_age_seconds = max_age_hours * 3600.0
        self.force_refresh = force_refresh
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verbose = verbose
        self._mem: dict[str, etree._Element] = {}

    def _log(self, msg: str, is_error: bool = False) -> None:
        """Print a log line when ``verbose`` is set.

        Args:
            msg: the text to print.
            is_error: route to stderr instead of stdout.
        """
        if self.verbose:
            print(msg, file=sys.stderr if is_error else sys.stdout)

    # ── path layout ──────────────────────────────────────────────────────────
    def lotl_path(self) -> Path:
        """Filesystem path of the cached LOTL file."""
        return self.cache_dir / "LOTL.xml"

    def national_path(self, country: str) -> Path:
        # Country code sanitised to avoid path traversal from unexpected input.
        """Filesystem path of the cached national TL.

        Args:
            country: ISO territory code, e.g. ``"CZ"``.
        """
        cc = "".join(ch for ch in (country or "XX") if ch.isalnum()) or "XX"
        return self.cache_dir / cc.upper() / "TL.xml"

    # ── staleness ────────────────────────────────────────────────────────────
    def _is_stale(self, path: Path, check_next_update: bool) -> bool:
        """Whether a cached file needs to be (re-)downloaded.

        Args:
            path: the cached file to test.
            check_next_update: also honour the TSL's ``NextUpdate`` field.
        Returns:
            True if the file is missing, force-refresh is set, it is older than
            ``max_age_hours``, or its NextUpdate has passed.
        """
        if self.force_refresh:
            return True
        if not path.exists():
            return True
        age = time.time() - path.stat().st_mtime
        if age > self.max_age_seconds:
            return True
        if check_next_update:
            nu = self._read_next_update(path)
            if nu is not None and datetime.now(timezone.utc) > nu:
                return True
        return False

    @staticmethod
    def _read_next_update(path: Path) -> Optional[datetime]:
        """Return the ``NextUpdate`` datetime from a cached TSL file, or None."""
        try:
            root = etree.parse(str(path)).getroot()
        except Exception:
            return None
        dt_text = root.findtext(f".//{_NS}NextUpdate/{_NS}dateTime")
        return _parse_xsd_datetime(dt_text) if dt_text else None

    # ── disk + network I/O ───────────────────────────────────────────────────
    @staticmethod
    def _load(path: Path) -> Optional[etree._Element]:
        """Parse a cached XML file and return its lxml root element."""
        try:
            return etree.fromstring(path.read_bytes())
        except Exception:
            return None

    def _download(self, url: str, label: str) -> Optional[bytes]:
        """Fetch a URL's bytes.

        Args:
            url: the URL to GET.
            label: a human-readable label used in log output.
        Returns:
            The response body, or None if the request failed.
        """
        try:
            self._log(f"  [fetch] {label or url}")
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            self._log(f"  [warn] Could not fetch {url}: {e}", is_error=True)
            return None

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        """Atomically write bytes to a cache path (temp file then rename)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(content)
        tmp.replace(path)  # atomic on the same filesystem

    # ── core get ─────────────────────────────────────────────────────────────
    def _get(self, url: str, path: Path, check_next_update: bool, label: str) -> Optional[etree._Element]:
        """Return a parsed XML root for ``url``, using or refreshing the cache.

        Args:
            url: source URL.
            path: cache location for the downloaded file.
            check_next_update: honour the TSL NextUpdate when judging staleness.
            label: log label for the download.
        Returns:
            The parsed lxml root, or None on failure.
        """
        if url in self._mem:
            return self._mem[url]

        root: Optional[etree._Element] = None
        if self._is_stale(path, check_next_update):
            content = self._download(url, label)
            if content is not None:
                try:
                    root = etree.fromstring(content)
                    self._write(path, content)  # only persist if it parses
                except Exception as e:
                    self._log(f"  [warn] {label}: downloaded content didn't parse: {e}",
                              is_error=True)
                    root = None
            if root is None and path.exists():
                self._log(f"  [info] {label}: using stale cached copy after fetch failure")
                root = self._load(path)
        else:
            self._log(f"  [cache] {label} (fresh on disk)")
            root = self._load(path)

        if root is not None:
            self._mem[url] = root
        return root

    # ── public API ───────────────────────────────────────────────────────────
    def get_lotl(self, url: str) -> Optional[etree._Element]:
        """Return the parsed LOTL root, downloading and caching as needed.

        Args:
            url: the List-of-Trusted-Lists URL.
        """
        return self._get(url, self.lotl_path(), check_next_update=True, label="EU LOTL")

    def get_national(self, country: str, url: str) -> Optional[etree._Element]:
        """Return a parsed national TL root, downloading and caching as needed.

        Args:
            country: ISO territory code.
            url: the national trusted-list URL.
        """
        return self._get(url, self.national_path(country),
                         check_next_update=False, label=f"TL [{country}]")


class EuTrustedListClient:
    """
    Resolves the EU LOTL into national Trusted List URLs and the qualified-CA
    certificates those lists contain. All XML fetching/caching is delegated to
    an XmlCache (persistent on disk); this class only handles parsing.

    Attributes:
        lotl_url: URL of the EU List-of-Trusted-Lists.
        cache: the ``XmlCache`` used for all downloads.
        verbose: when True, fetch activity is printed.
        _national_urls: cached list of {country, url} dicts (None until
            ``national_tl_urls()`` is first called).
        _all_certs: cached union of qualified-CA DER certs (None until
            ``all_qualified_ca_certs()`` runs unfiltered).
    """

    def __init__(self, lotl_url: str = DEFAULT_LOTL_URL,
                 cache: Optional[XmlCache] = None, verbose: bool = True):
        """Args:
            lotl_url: URL of the EU List-of-Trusted-Lists.
            cache: an ``XmlCache`` used for all downloads.
            verbose: when True, print fetch activity (errors to stderr).
        """
        self.lotl_url = lotl_url
        self.cache = cache or XmlCache(verbose=verbose)
        self.verbose = verbose
        self._national_urls: Optional[list[dict]] = None
        self._all_certs: Optional[list[bytes]] = None

    def _log(self, msg: str, is_error: bool = False) -> None:
        """Print a log line when ``verbose`` is set.

        Args:
            msg: the text to print.
            is_error: route to stderr instead of stdout.
        """
        if self.verbose:
            print(msg, file=sys.stderr if is_error else sys.stdout)

    # ── LOTL → national TL URLs ──────────────────────────────────────────────
    def national_tl_urls(self) -> list[dict]:
        """
        Return [{"country": "CZ", "url": "...xtsl"}, ...].

        Pointers are selected by MIME type (application/vnd.etsi.tsl+xml), not
        file extension, because national TLs use varied extensions (.xml,
        .xtsl, query strings). The human-readable PDF renderings are excluded.
        """
        if self._national_urls is not None:
            return self._national_urls

        lotl = self.cache.get_lotl(self.lotl_url)
        urls: list[dict] = []
        if lotl is not None:
            seen: set[str] = set()
            for ptr in lotl.iter(f"{_NS}OtherTSLPointer"):
                loc = ptr.findtext(f"{_NS}TSLLocation")
                if not loc:
                    continue
                territory = ptr.findtext(f".//{_NS}SchemeTerritory") or "??"
                mime = ptr.findtext(f".//{_TSLX}MimeType")
                is_xml_tl = (mime == _TSL_XML_MIME) if mime else not loc.lower().endswith(".pdf")
                if not is_xml_tl or loc in seen:
                    continue
                seen.add(loc)
                urls.append({"country": territory, "url": loc})

        self._national_urls = urls
        return urls

    # ── national TL XML → qualified CA certs ─────────────────────────────────
    @staticmethod
    def qualified_ca_certs_from_tl(tl_root: etree._Element) -> list[bytes]:
        """Extract DER certs for all CA/QC services with a 'granted' status."""
        der_certs: list[bytes] = []
        for svc in tl_root.iter(f"{_NS}TSPService"):
            svc_type = svc.findtext(
                f"{_NS}ServiceInformation/{_NS}ServiceTypeIdentifier"
            )
            if svc_type != QUALIFIED_CA_SVCTYPE:
                continue
            status = svc.findtext(
                f"{_NS}ServiceInformation/{_NS}ServiceStatus"
            )
            if status not in GRANTED_STATUSES:
                continue
            for di in svc.iter(f"{_NS}DigitalId"):
                b64 = di.findtext(f"{_NS}X509Certificate")
                if b64:
                    try:
                        der_certs.append(base64.b64decode(b64.strip()))
                    except Exception:
                        pass
        return der_certs

    def all_qualified_ca_certs(self, countries: Optional[Iterable[str]] = None,
                               progress=None) -> list[bytes]:
        """
        Resolve every (or a filtered set of) national TL and return the union
        of qualified-CA DER certificates. Result is cached when unfiltered.

        countries: optional iterable of ISO codes (e.g. {"CZ", "DE"}) to limit
                   which national lists are consulted.
        progress:  optional callable(done:int, total:int, country:str) invoked
                   before each national TL is consulted, for UI progress bars.
        """
        if countries is None and self._all_certs is not None:
            return self._all_certs

        wanted = {c.upper() for c in countries} if countries else None
        entries = [e for e in self.national_tl_urls()
                   if wanted is None or e["country"].upper() in wanted]
        total = len(entries)

        certs: list[bytes] = []
        for i, entry in enumerate(entries, 1):
            if progress is not None:
                try:
                    progress(i, total, entry["country"])
                except Exception:
                    pass
            try:
                tl_root = self.cache.get_national(entry["country"], entry["url"])
                if tl_root is not None:
                    certs.extend(self.qualified_ca_certs_from_tl(tl_root))
            except Exception as e:
                self._log(f"  [warn] TL [{entry['country']}] failed: {e}", is_error=True)

        if countries is None:
            self._all_certs = certs
        return certs


# ══════════════════════════════════════════════════════════════════════════════
# 3. Build a pyhanko ValidationContext from trusted certificates
# ══════════════════════════════════════════════════════════════════════════════

class ValidationContextBuilder:
    """
    Accumulates trusted DER certificates and builds a pyhanko ValidationContext
    that uses them as trust anchors.

    Attributes:
        allow_revocation_fetch: when True, validation requires revocation info
            and fetches OCSP/CRL online (hard-fail); when False it soft-fails.
        _der_certs: accumulated DER-encoded trust-anchor certificates.
    """

    def __init__(self, allow_revocation_fetch: bool = False):
        # When True: require revocation info and fetch OCSP/CRL online
        # (hard-fail). When False: soft-fail (don't reject if revocation info
        # is simply unavailable / offline).
        """Args:
            allow_revocation_fetch: when True, permit OCSP/CRL network fetches
                during validation; when False, validation is offline.
        """
        self.allow_revocation_fetch = allow_revocation_fetch
        self._der_certs: list[bytes] = []

    def add_certs(self, der_certs: Iterable[bytes]) -> "ValidationContextBuilder":
        """Add several trust-anchor certificates.

        Args:
            der_certs: an iterable of DER-encoded certificates.
        Returns:
            self, to allow chaining.
        """
        self._der_certs.extend(der_certs)
        return self

    def add_cert(self, der_cert: bytes) -> "ValidationContextBuilder":
        """Add a single DER-encoded trust anchor.

        Args:
            der_cert: the DER-encoded certificate bytes.
        Returns:
            self, to allow chaining.
        """
        self._der_certs.append(der_cert)
        return self

    @property
    def trust_root_count(self) -> int:
        """Number of trust anchors accumulated so far."""
        return len(self._der_certs)

    def build(self):
        """Build a pyHanko ``ValidationContext`` from the accumulated anchors."""
        from pyhanko_certvalidator import ValidationContext
        from asn1crypto import x509 as asn1x509

        trust_roots = []
        for der in self._der_certs:
            try:
                trust_roots.append(asn1x509.Certificate.load(der))
            except Exception:
                pass

        return ValidationContext(
            trust_roots=trust_roots,
            revocation_mode="hard-fail" if self.allow_revocation_fetch else "soft-fail",
            allow_fetching=self.allow_revocation_fetch,
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Parse QCStatements from a certificate (taken from a SignatureInfo)
# ══════════════════════════════════════════════════════════════════════════════

class QcStatementParser:
    """
    Parses the id-etsi-ext-qcStatements extension (OID 1.3.6.1.5.5.7.1.3) per
    ETSI EN 319 412-5.

        QCStatements ::= SEQUENCE OF QCStatement
        QCStatement  ::= SEQUENCE {
            statementId   OBJECT IDENTIFIER,
            statementInfo ANY DEFINED BY statementId OPTIONAL
        }

    Most statements (QcCompliance, QcSSCD) are identified by statementId alone.
    The QcType statement is nested:

        statementId   = 0.4.0.1862.1.6   (id-etsi-qcs-QcType)
        statementInfo = QcType ::= SEQUENCE OF OBJECT IDENTIFIER

    The esign/eseal/web OIDs (…1.6.1 / .2 / .3) are *values inside* that nested
    sequence, NOT statement IDs — so detecting "natural person" requires opening
    the QcType statement's statementInfo and walking its OID list.

    This parser is stateless (it holds no instance attributes); each call is
    independent.
    """

    def parse_certificate(self, cert: x509.Certificate) -> QcInfo:
        """Parse a certificate's QCStatements extension into a ``QcInfo``.

        Args:
            cert: a cryptography ``x509.Certificate``.
        Returns:
            A populated ``QcInfo`` (empty/false fields when no QCStatements).
        """
        info = QcInfo()
        try:
            ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(OID_QC_STATEMENTS)
            )
        except x509.ExtensionNotFound:
            return info

        info.has_qc_statements = True
        try:
            from asn1crypto import core as asn1core

            raw_value = ext.value.value  # DER of QCStatements
            statements = asn1core.SequenceOf.load(raw_value)

            for stmt in statements:
                try:
                    body = stmt.contents  # statementId TLV [+ statementInfo TLV]
                    stmt_id_obj = asn1core.ObjectIdentifier.load(body)  # first TLV
                    stmt_id = stmt_id_obj.dotted
                    info.statement_ids.append(stmt_id)

                    info_bytes = body[len(stmt_id_obj.dump()):]  # remainder

                    if stmt_id == OID_QC_COMPLIANCE:
                        info.qc_compliance = True
                    elif stmt_id == OID_QC_SSCD:
                        info.qc_sscd = True
                    elif stmt_id == OID_QC_TYPE and info_bytes:
                        self._parse_qc_type(info_bytes, info)
                except Exception:
                    # Skip a malformed statement, keep parsing the rest
                    pass
        except Exception:
            pass

        return info

    @staticmethod
    def _parse_qc_type(info_bytes: bytes, info: QcInfo) -> None:
        """statementInfo = QcType ::= SEQUENCE OF OBJECT IDENTIFIER."""
        from asn1crypto import core as asn1core
        qc_types = asn1core.SequenceOf.load(info_bytes)
        for t in qc_types:
            try:
                type_oid = asn1core.ObjectIdentifier.load(t.dump()).dotted
            except Exception:
                continue
            info.qc_type_oids.append(type_oid)
            if type_oid == OID_QCT_ESIGN:
                info.qct_esign = True
            elif type_oid == OID_QCT_ESEAL:
                info.qct_eseal = True
            elif type_oid == OID_QCT_WEB:
                info.qct_web = True

    def parse_signature(self, sig: SignatureInfo) -> QcInfo:
        """Convenience: pull the signer certificate out of a SignatureInfo."""
        if sig.signer_cert is None:
            return QcInfo()
        return self.parse_certificate(sig.signer_cert)


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator + CLI
# ══════════════════════════════════════════════════════════════════════════════

def check_pdf(pdf_path: str, hard_revocation: bool = False,
              lotl_url: str = DEFAULT_LOTL_URL,
              cache_dir: str = "cache", refresh_cache: bool = False,
              max_age_hours: float = 24.0) -> None:
    # Silence pyhanko's expected path-building ERROR logs for untrusted sigs.
    """Validate a PDF's signatures and print a human-readable report.

    Args:
        pdf_path: path to the PDF to check.
        hard_revocation: require and fetch OCSP/CRL revocation information.
        lotl_url: the List-of-Trusted-Lists URL.
        cache_dir: on-disk XML cache directory.
        refresh_cache: force a re-download of the trusted lists.
        max_age_hours: cache freshness window in hours.
    """
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)

    print(f"\n{'='*70}")
    print(f"  EU Qualified Signature Check")
    print(f"  File: {pdf_path}")
    print(f"{'='*70}\n")

    qc_parser = QcStatementParser()

    with SignedPdf(pdf_path) as pdf:
        if not pdf.has_signatures:
            print("  No signatures found in this PDF.")
            return
        print(f"► Found {len(pdf.signatures)} signature(s).\n")

        # ── Resolve the EU Trusted Lists and collect qualified CA certs ──────
        print(f"► Fetching EU Trusted Lists (cache: {cache_dir}/)...")
        xml_cache = XmlCache(cache_dir=cache_dir, max_age_hours=max_age_hours,
                             force_refresh=refresh_cache)
        tl_client = EuTrustedListClient(lotl_url=lotl_url, cache=xml_cache)
        national = tl_client.national_tl_urls()
        print(f"  {len(national)} national Trusted Lists referenced.")
        trusted_certs = tl_client.all_qualified_ca_certs()
        print(f"  Collected {len(trusted_certs)} qualified CA certificate(s).\n")

        # ── Build the validation context (TL certs as trust anchors) ─────────
        vc = (ValidationContextBuilder(allow_revocation_fetch=hard_revocation)
              .add_certs(trusted_certs)
              .build())

        # ── Analyse each signature ──────────────────────────────────────────
        for sig in pdf.signatures:
            print(f"{'─'*70}")
            print(f"Signature field : {sig.field_name}")

            if sig.error or sig.signer_cert is None:
                print(f"  ⚠  Could not extract signer certificate: {sig.error}")
                continue

            sc = sig.signer_cert
            print(f"  Signer CN      : {cert_subject_cn(sc)}")
            print(f"  Issuer         : {sc.issuer.rfc4514_string()}")
            print(f"  Valid from/to  : {sc.not_valid_before_utc} → {sc.not_valid_after_utc}")

            # Cryptographic validation (signature + path to a TL trust anchor)
            v = pdf.validate(sig, vc)
            if v.error:
                print(f"\n  ⚠  Validation error: {v.error}")
            print(f"\n  Signature intact (unmodified) : {v.intact}")
            print(f"  CMS signature cryptographically valid : {v.valid}")
            print(f"  Chains+validates to EU TL anchor : {v.trusted}")
            print(f"  Revoked        : {v.revoked}")
            print(f"  Coverage       : {v.coverage}")

            # QCStatements on the signer cert (parser pulls cert from the sig)
            qc = qc_parser.parse_signature(sig)
            print(f"\n  QCStatements present : {qc.has_qc_statements}")
            if qc.has_qc_statements:
                print(f"    QcCompliance (is qualified)   : {qc.qc_compliance}")
                print(f"    QcSSCD (key in secure device) : {qc.qc_sscd}")
                print(f"    QCType esign (natural person) : {qc.qct_esign}")
                print(f"    QCType eseal (legal person)   : {qc.qct_eseal}")
                print(f"    QCType web auth               : {qc.qct_web}")
                if qc.statement_ids:
                    print(f"    Statement IDs : {', '.join(qc.statement_ids)}")
                if qc.qc_type_oids:
                    print(f"    QcType values : {', '.join(qc.qc_type_oids)}")

            # Final verdict
            print()
            fully_trusted = v.cryptographically_sound and v.trusted and not v.revoked
            if fully_trusted and qc.is_qualified_natural_person:
                print("  🏆 QUALIFIED ELECTRONIC SIGNATURE — natural person (eIDAS Art. 3(12))")
            elif fully_trusted and qc.is_qualified_legal_person:
                print("  🏆 QUALIFIED ELECTRONIC SEAL — legal person (eIDAS Art. 3(27))")
            elif fully_trusted:
                print("  ✅ Validates to an EU trusted CA, but cert lacks a qualified-sig QCStatement.")
            elif v.cryptographically_sound:
                print("  ⚠️  Cryptographically valid but does NOT chain to an EU TL anchor.")
            else:
                print("  ❌ Failed cryptographic validation (modified, invalid, or revoked).")

    print(f"\n{'='*70}\n")


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point.

    Args:
        argv: optional argument vector (defaults to ``sys.argv[1:]``).
    """
    ap = argparse.ArgumentParser(description="Check EU qualified signatures in a PDF.")
    ap.add_argument("pdf", help="Path to the PDF file")
    ap.add_argument("--hard-revocation", action="store_true",
                    help="Require revocation info (OCSP/CRL) and fetch it online "
                         "(default: soft-fail, no network revocation check)")
    ap.add_argument("--lotl-url", default=DEFAULT_LOTL_URL,
                    help="Override the EU LOTL URL")
    ap.add_argument("--cache", default=default_cache_dir(), metavar="DIR",
                    help="Directory for the on-disk LOTL/TL XML cache "
                         "(default: $XDG_CACHE_HOME/sigviewer)")
    ap.add_argument("--refresh-cache", action="store_true",
                    help="Force re-download of LOTL and all TL XML, ignoring "
                         "the on-disk cache")
    ap.add_argument("--max-age-hours", type=float, default=24.0, metavar="H",
                    help="Re-download a cached XML once its file is older than "
                         "this many hours (default: 24)")
    args = ap.parse_args(argv)

    if not Path(args.pdf).exists():
        print(f"File not found: {args.pdf}")
        return 1

    check_pdf(args.pdf, hard_revocation=args.hard_revocation, lotl_url=args.lotl_url,
              cache_dir=args.cache, refresh_cache=args.refresh_cache,
              max_age_hours=args.max_age_hours)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
