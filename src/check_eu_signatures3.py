#!/usr/bin/env python3
"""
EU Qualified PDF Signature Checker
====================================
For each signature in a PDF:
  1. Extracts the signer's certificate chain
  2. Downloads the EU LOTL and relevant national Trusted Lists
  3. Checks whether any cert in the chain is issued by a Qualified CA
  4. Reports whether the cert carries a QCStatement for natural persons
     (id-etsi-qct-esign) as per ETSI EN 319 412-5

Usage:
    python check_eu_signatures.py <path-to-pdf>

Requirements:
    pip install pyhanko pyhanko-certvalidator endesive lxml requests cryptography
"""

import sys
import hashlib
import requests
import traceback
from pathlib import Path
from typing import Optional

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend

# ── OIDs ──────────────────────────────────────────────────────────────────────
# id-etsi-ext-qcStatements  (RFC 3739 / ETSI EN 319 412-5)
OID_QC_STATEMENTS       = "1.3.6.1.5.5.7.1.3"
# QC-type statements (ETSI EN 319 412-5 §4.2.3)
OID_QCT_ESIGN           = "0.4.0.1862.1.6.1"   # Natural person e-signature
OID_QCT_ESEAL           = "0.4.0.1862.1.6.2"   # Legal person e-seal
OID_QCT_WEB             = "0.4.0.1862.1.6.3"   # Website authentication
# QcCompliance – this cert is qualified
OID_QC_COMPLIANCE       = "0.4.0.1862.1.1"
# QcSSCD – private key is in SSCD (secure device)
OID_QC_SSCD             = "0.4.0.1862.1.4"
OID_QC_TYPE             = "0.4.0.1862.1.6"

# EU LOTL (List of Trusted Lists) – the master entry point
LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

TL_NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "tslx": "http://uri.etsi.org/02231/v2/additionaltypes#",
    "ecc": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# Service types that issue qualified certificates
QUALIFIED_CA_SVCTYPE = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
# Status values that count as "granted" (active)
GRANTED_STATUSES = {
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. PDF signature extraction
# ══════════════════════════════════════════════════════════════════════════════

def extract_signatures(pdf_path: str) -> list[dict]:
    """
    Returns a list of dicts, one per signature:
        {
          "name": str,
          "signer_cert": cryptography.x509.Certificate | None,
          "chain": [cryptography.x509.Certificate],   # signer first, deduped
          "coverage": str,        # how much of the doc the sig covers
          "modified": bool|None,  # whether the doc was modified after signing
        }
    Uses pyhanko's embedded_signatures API, which resolves indirect objects
    and parses the CMS for us (no manual /Contents decoding).
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from cryptography.hazmat.backends import default_backend

    def _to_crypto(asn1_cert):
        """Convert an asn1crypto certificate to a cryptography certificate."""
        return x509.load_der_x509_certificate(asn1_cert.dump(), default_backend())

    results = []
    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f)
        embedded = list(reader.embedded_signatures)

        if not embedded:
            return results

        for emb in embedded:
            entry = {
                "name": emb.field_name,
                "signer_cert": None,
                "chain": [],
                "coverage": None,
                "modified": None,
            }
            try:
                signer = _to_crypto(emb.signer_cert)

                # Build chain: signer first, then any other embedded certs,
                # deduped by fingerprint.
                chain = [signer]
                seen = {cert_fingerprint(signer)}
                for c in (emb.other_embedded_certs or []):
                    try:
                        cc = _to_crypto(c)
                        fp = cert_fingerprint(cc)
                        if fp not in seen:
                            seen.add(fp)
                            chain.append(cc)
                    except Exception:
                        pass

                entry["signer_cert"] = signer
                entry["chain"] = chain

                # Optional: report document coverage / tampering
                try:
                    cov = emb.evaluate_signature_coverage()
                    entry["coverage"] = str(cov)
                except Exception:
                    pass

            except Exception as e:
                entry["error"] = str(e)

            results.append(entry)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 2. EU Trusted List download & parsing
# ══════════════════════════════════════════════════════════════════════════════

_tl_cache: dict[str, etree._Element] = {}   # URL → parsed XML root


def _fetch_xml(url: str, label: str = "") -> Optional[etree._Element]:
    """Download and parse an XML document, with simple in-memory caching."""
    if url in _tl_cache:
        return _tl_cache[url]
    try:
        print(f"  [fetch] {label or url}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        root = etree.fromstring(resp.content)
        _tl_cache[url] = root
        return root
    except Exception as e:
        print(f"  [warn] Could not fetch {url}: {e}")
        return None


def get_national_tl_urls() -> list[dict]:
    """
    Parse the EU LOTL and return a list of:
        {"country": "CZ", "url": "https://...xtsl"}

    Filters pointers by MIME type (application/vnd.etsi.tsl+xml) rather than
    file extension, because national TLs use varied extensions (.xml, .xtsl,
    query strings, etc.). The LOTL also lists a human-readable PDF version of
    each list — those (application/pdf) are excluded.
    """
    lotl = _fetch_xml(LOTL_URL, "EU LOTL (master list)")
    if lotl is None:
        return []

    NS = "{http://uri.etsi.org/02231/v2#}"
    TSLX = "{http://uri.etsi.org/02231/v2/additionaltypes#}"
    TSL_XML_MIME = "application/vnd.etsi.tsl+xml"

    urls = []
    seen = set()
    for ptr in lotl.iter(f"{NS}OtherTSLPointer"):
        loc = ptr.findtext(f"{NS}TSLLocation")
        if not loc:
            continue

        territory = ptr.findtext(f".//{NS}SchemeTerritory") or "??"
        mime = ptr.findtext(f".//{TSLX}MimeType")

        # Prefer the declared MIME type. If absent, fall back to: accept
        # anything that isn't obviously the PDF rendering.
        if mime:
            is_xml_tl = (mime == TSL_XML_MIME)
        else:
            is_xml_tl = not loc.lower().endswith(".pdf")

        if not is_xml_tl or loc in seen:
            continue

        seen.add(loc)
        urls.append({"country": territory, "url": loc})

    return urls


def get_qualified_ca_certs_from_tl(tl_root: etree._Element) -> list[bytes]:
    """
    From a national Trusted List XML, extract DER-encoded certificates
    for all services of type CA/QC with status 'granted'.
    """
    der_certs = []
    import base64

    for svc in tl_root.iter("{http://uri.etsi.org/02231/v2#}TSPService"):
        svc_type = svc.findtext(
            "{http://uri.etsi.org/02231/v2#}ServiceInformation"
            "/{http://uri.etsi.org/02231/v2#}ServiceTypeIdentifier"
        )
        if svc_type != QUALIFIED_CA_SVCTYPE:
            continue

        status = svc.findtext(
            "{http://uri.etsi.org/02231/v2#}ServiceInformation"
            "/{http://uri.etsi.org/02231/v2#}ServiceStatus"
        )
        if status not in GRANTED_STATUSES:
            continue

        # Collect all digital identities (certificates) for this service
        for di in svc.iter("{http://uri.etsi.org/02231/v2#}DigitalId"):
            b64 = di.findtext("{http://uri.etsi.org/02231/v2#}X509Certificate")
            if b64:
                try:
                    der_certs.append(base64.b64decode(b64.strip()))
                except Exception:
                    pass

    return der_certs


def cert_fingerprint(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Chain validation against trusted list
# ══════════════════════════════════════════════════════════════════════════════

def build_validation_context(trusted_der_certs: list[bytes], allow_revocation_fetch: bool = False):
    """
    Build a pyhanko ValidationContext using the EU TL qualified-CA certs as
    trust roots. asn1crypto certs are what pyhanko expects.
    """
    from pyhanko_certvalidator import ValidationContext
    from asn1crypto import x509 as asn1x509

    trust_roots = []
    for der in trusted_der_certs:
        try:
            trust_roots.append(asn1x509.Certificate.load(der))
        except Exception:
            pass

    # soft-fail: don't reject if revocation info is simply unavailable; if you
    # need hard revocation guarantees set revocation_mode="hard-fail" and
    # allow_fetching=True (needs network access to OCSP/CRL endpoints).
    return ValidationContext(
        trust_roots=trust_roots,
        revocation_mode="hard-fail" if allow_revocation_fetch else "soft-fail",
        allow_fetching=allow_revocation_fetch,
    )


def validate_signature(embedded_sig, validation_context) -> dict:
    """
    Run full cryptographic validation of one embedded signature:
      - CMS signature verifies over the signed bytes  (valid)
      - document not modified within signature coverage (intact)
      - a validation path builds to a TL trust root      (trusted)
      - revocation status                                 (revoked)

    Returns a dict of the salient status flags. pyhanko logs internal
    path-building failures at ERROR level; those are expected for untrusted
    signatures and are silenced by the caller.
    """
    from pyhanko.sign.validation import validate_pdf_signature

    out = {
        "valid": False, "intact": False, "trusted": False,
        "revoked": None, "coverage": None, "bottom_line": False,
        "summary": "", "error": None,
    }
    try:
        st = validate_pdf_signature(embedded_sig, validation_context)
        out.update(
            valid=bool(st.valid),
            intact=bool(st.intact),
            trusted=bool(st.trusted),
            revoked=bool(st.revoked),
            coverage=str(st.coverage),
            bottom_line=bool(st.bottom_line),
            summary=st.summary() if callable(getattr(st, "summary", None)) else str(st.summary),
        )
    except Exception as e:
        out["error"] = str(e)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# 4. QCStatement analysis
# ══════════════════════════════════════════════════════════════════════════════

def parse_qc_statements(cert: x509.Certificate) -> dict:
    """
    Parse the id-etsi-ext-qcStatements extension (OID 1.3.6.1.5.5.7.1.3).
    Returns a dict:
        {
          "has_qc_statements": bool,
          "qct_esign": bool,   # natural person
          "qct_eseal": bool,   # legal person / seal
          "qct_web": bool,     # website auth
          "qc_compliance": bool,
          "qc_sscd": bool,
          "raw_oids": [str],
        }
    """
    result = {
        "has_qc_statements": False,
        "qct_esign": False,
        "qct_eseal": False,
        "qct_web": False,
        "qc_compliance": False,
        "qc_sscd": False,
        "raw_oids": [],
    }

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_QC_STATEMENTS)
        )
        result["has_qc_statements"] = True

        # The extension value is opaque to the high-level cryptography API,
        # so we use asn1crypto to decode it.
        from asn1crypto import core as asn1core, pem as asn1pem

        raw_value = ext.value.value  # DER bytes of the extension value

        # QCStatements ::= SEQUENCE OF QCStatement
        # QCStatement  ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }
        # Each item in the outer SEQUENCE is a QCStatement (inner SEQUENCE).
        # item.contents = the body of that inner SEQUENCE, starting with the OID TLV.
        seq = asn1core.SequenceOf.load(raw_value)

        for stmt in seq:
            try:
                # stmt.contents is the body of the QCStatement SEQUENCE,
                # which starts with the OID TLV.
                oid_val = asn1core.ObjectIdentifier.load(stmt.contents).dotted
                result["raw_oids"].append(oid_val)

                if oid_val == OID_QC_TYPE:
                    result["qct_esign"] = True
                elif oid_val == OID_QCT_ESEAL:
                    result["qct_eseal"] = True
                elif oid_val == OID_QCT_WEB:
                    result["qct_web"] = True
                elif oid_val == OID_QC_COMPLIANCE:
                    result["qc_compliance"] = True
                elif oid_val == OID_QC_SSCD:
                    result["qc_sscd"] = True
            except Exception:
                pass

    except (x509.ExtensionNotFound, Exception):
        pass

    return result


def cert_subject_cn(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except Exception:
        return cert.subject.rfc4514_string()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Main orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def check_pdf(pdf_path: str, hard_revocation: bool = False):
    import logging
    from cryptography.hazmat.backends import default_backend
    from pyhanko.pdf_utils.reader import PdfFileReader

    # Silence pyhanko's expected path-building ERROR logs for untrusted sigs.
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)

    def _to_crypto(asn1_cert):
        return x509.load_der_x509_certificate(asn1_cert.dump(), default_backend())

    print(f"\n{'='*70}")
    print(f"  EU Qualified Signature Check")
    print(f"  File: {pdf_path}")
    print(f"{'='*70}\n")

    # Keep the PDF open for the whole run — validation needs to re-read bytes.
    with open(pdf_path, "rb") as f:
        try:
            reader = PdfFileReader(f)
            embedded = list(reader.embedded_signatures)
        except Exception as e:
            print(f"  ERROR reading PDF: {e}")
            traceback.print_exc()
            return

        if not embedded:
            print("  No signatures found in this PDF.")
            return

        print(f"► Found {len(embedded)} signature(s).\n")

        # ── Download LOTL + national TLs, collect qualified CA certs ─────────
        print("► Fetching EU List of Trusted Lists (LOTL)...")
        national_tl_entries = get_national_tl_urls()
        print(f"  {len(national_tl_entries)} national Trusted Lists referenced.")

        all_trusted_der: list[bytes] = []
        print("► Downloading national Trusted Lists (qualified CA certs)...")
        for entry in national_tl_entries:
            try:
                tl_root = _fetch_xml(entry["url"], f"TL [{entry['country']}]")
                if tl_root is not None:
                    all_trusted_der.extend(get_qualified_ca_certs_from_tl(tl_root))
            except Exception as e:
                print(f"  [warn] TL [{entry['country']}] failed: {e}")
        print(f"  Collected {len(all_trusted_der)} qualified CA certificate(s).\n")

        # ── Build the validation context (TL certs as trust roots) ───────────
        vc = build_validation_context(all_trusted_der, allow_revocation_fetch=hard_revocation)

        # ── Analyse each signature ──────────────────────────────────────────
        for emb in embedded:
            print(f"{'─'*70}")
            print(f"Signature field : {emb.field_name}")

            try:
                signer = _to_crypto(emb.signer_cert)
            except Exception as e:
                print(f"  ⚠  Could not extract signer certificate: {e}")
                continue

            print(f"  Signer CN      : {cert_subject_cn(signer)}")
            print(f"  Issuer         : {signer.issuer.rfc4514_string()}")
            print(f"  Valid from/to  : {signer.not_valid_before_utc} → {signer.not_valid_after_utc}")

            # ── Cryptographic validation (signature + path to TL root) ──────
            v = validate_signature(emb, vc)
            if v["error"]:
                print(f"\n  ⚠  Validation error: {v['error']}")
            print(f"\n  Signature intact (unmodified) : {v['intact']}")
            print(f"  CMS signature cryptographically valid : {v['valid']}")
            print(f"  Chains+validates to EU TL root : {v['trusted']}")
            print(f"  Revoked        : {v['revoked']}")
            print(f"  Coverage       : {v['coverage']}")

            # ── QCStatements on the signer cert ─────────────────────────────
            qc = parse_qc_statements(signer)
            print(f"\n  QCStatements present : {qc['has_qc_statements']}")
            if qc["has_qc_statements"]:
                print(f"    QcCompliance (is qualified)   : {qc['qc_compliance']}")
                print(f"    QcSSCD (key in secure device) : {qc['qc_sscd']}")
                print(f"    QCType esign (natural person) : {qc['qct_esign']}")
                print(f"    QCType eseal (legal person)   : {qc['qct_eseal']}")
                print(f"    QCType web auth               : {qc['qct_web']}")
                if qc["raw_oids"]:
                    print(f"    All QC OIDs : {', '.join(qc['raw_oids'])}")

            # ── Final verdict ───────────────────────────────────────────────
            # A Qualified Electronic Signature requires ALL of:
            #   intact + cryptographically valid + path to a TL qualified CA
            #   + QcCompliance + natural-person QCType.
            print()
            fully_trusted = v["intact"] and v["valid"] and v["trusted"] and not v["revoked"]
            if fully_trusted and qc["qc_compliance"] and qc["qct_esign"]:
                print("  🏆 QUALIFIED ELECTRONIC SIGNATURE — natural person (eIDAS Art. 3(12))")
            elif fully_trusted and qc["qc_compliance"] and qc["qct_eseal"]:
                print("  🏆 QUALIFIED ELECTRONIC SEAL — legal person (eIDAS Art. 3(27))")
            elif fully_trusted:
                print("  ✅ Validates to an EU trusted CA, but cert lacks a qualified-sig QCStatement.")
            elif v["intact"] and v["valid"]:
                print("  ⚠️  Signature is cryptographically valid but does NOT chain to an EU TL root.")
            else:
                print("  ❌ Signature failed cryptographic validation (modified, invalid, or revoked).")

    print(f"\n{'='*70}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Check EU qualified signatures in a PDF.")
    ap.add_argument("pdf", help="Path to the PDF file")
    ap.add_argument("--hard-revocation", action="store_true",
                    help="Require revocation info (OCSP/CRL) and fetch it online "
                         "(default: soft-fail, no network revocation check)")
    args = ap.parse_args()

    if not Path(args.pdf).exists():
        print(f"File not found: {args.pdf}")
        sys.exit(1)

    check_pdf(args.pdf, hard_revocation=args.hard_revocation)
