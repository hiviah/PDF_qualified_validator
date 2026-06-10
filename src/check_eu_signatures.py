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
    Returns a list of dicts, one per signature field:
        {
          "name": str,
          "signer_cert": cryptography.x509.Certificate | None,
          "chain": [cryptography.x509.Certificate],   # signer first
          "raw_pkcs7": bytes,
        }
    Uses pyhanko for extraction.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import enumerate_sig_fields

    results = []
    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f)
        sig_fields = list(enumerate_sig_fields(reader))

        if not sig_fields:
            return results

        for field_name, sig_obj, field_mdp_info in sig_fields:
            if sig_obj is None:
                continue

            entry = {"name": field_name, "signer_cert": None, "chain": [], "raw_pkcs7": b""}
            try:
                # sig_obj is a DictionaryObject; get the raw CMS/PKCS#7 bytes
                contents = sig_obj.get("/Contents")
                if contents is None:
                    continue

                # pyhanko stores the raw bytes as a ByteStringObject
                raw = bytes(contents)
                entry["raw_pkcs7"] = raw

                # Parse the CMS SignedData with cryptography library
                from cryptography.hazmat.primitives.serialization.pkcs7 import (
                    load_der_pkcs7_certificates,
                )
                certs = load_der_pkcs7_certificates(raw)
                if certs:
                    # Heuristic: signer cert has the lowest path length / no CA flag
                    # More robustly: find the cert whose subject matches the SignerInfo
                    entry["chain"] = list(certs)
                    # Pick end-entity: cert with no CA basic constraint, or smallest path
                    signer = _find_end_entity(certs)
                    entry["signer_cert"] = signer

            except Exception as e:
                entry["error"] = str(e)

            results.append(entry)

    return results


def _find_end_entity(certs) -> Optional[x509.Certificate]:
    """Return the most likely signer (end-entity) certificate from a PKCS#7 bag."""
    for cert in certs:
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                return cert
        except x509.ExtensionNotFound:
            # No BasicConstraints → likely an EE cert
            return cert
    # Fallback: first cert
    return certs[0] if certs else None


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
        {"country": "DE", "url": "https://..."}
    """
    lotl = _fetch_xml(LOTL_URL, "EU LOTL (master list)")
    if lotl is None:
        return []

    urls = []
    # OtherTSLPointer elements for member state TLs
    for ptr in lotl.iter("{http://uri.etsi.org/02231/v2#}OtherTSLPointer"):
        loc = ptr.findtext("{http://uri.etsi.org/02231/v2#}TSLLocation")
        if loc and loc.endswith(".xml"):
            # Try to extract the scheme territory (country code)
            territory = ptr.findtext(
                ".//{http://uri.etsi.org/02231/v2#}SchemeTerritory"
            ) or "??"
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
    return cert.fingerprint(cert.signature_hash_algorithm or __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Chain validation against trusted list
# ══════════════════════════════════════════════════════════════════════════════

def chain_to_trusted_ca(
    chain: list[x509.Certificate],
    trusted_der_certs: list[bytes],
) -> Optional[x509.Certificate]:
    """
    Walk the certificate chain and return the first cert whose issuer
    matches one of the trusted CA certs from the EU TL.
    Returns None if no match found.
    """
    trusted = []
    for der in trusted_der_certs:
        try:
            trusted.append(x509.load_der_x509_certificate(der, default_backend()))
        except Exception:
            pass

    # Build a set of trusted CA subjects (as DER bytes for fast comparison)
    trusted_subjects = {c.subject.public_bytes(): c for c in trusted}

    for cert in chain:
        issuer_bytes = cert.issuer.public_bytes()
        if issuer_bytes in trusted_subjects:
            return trusted_subjects[issuer_bytes]

    return None


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

                if oid_val == OID_QCT_ESIGN:
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

def check_pdf(pdf_path: str):
    print(f"\n{'='*70}")
    print(f"  EU Qualified Signature Check")
    print(f"  File: {pdf_path}")
    print(f"{'='*70}\n")

    # ── Step 1: extract signatures ───────────────────────────────────────────
    print("► Extracting signatures from PDF...")
    try:
        sigs = extract_signatures(pdf_path)
    except Exception as e:
        print(f"  ERROR reading PDF: {e}")
        traceback.print_exc()
        return

    if not sigs:
        print("  No signatures found in this PDF.")
        return

    print(f"  Found {len(sigs)} signature(s).\n")

    # ── Step 2: download LOTL and national TLs ───────────────────────────────
    print("► Fetching EU List of Trusted Lists (LOTL)...")
    national_tl_entries = get_national_tl_urls()
    print(f"  Found {len(national_tl_entries)} national Trusted Lists.\n")

    # Collect ALL trusted CA DER certs across all countries
    # (lazy: download as needed, cache by URL)
    all_trusted_der: list[bytes] = []

    def ensure_all_tls_loaded():
        """Download all national TLs and collect qualified CA certs."""
        for entry in national_tl_entries:
            tl_root = _fetch_xml(entry["url"], f"TL [{entry['country']}]")
            if tl_root is not None:
                certs = get_qualified_ca_certs_from_tl(tl_root)
                all_trusted_der.extend(certs)

    print("► Downloading national Trusted Lists and extracting qualified CA certs...")
    ensure_all_tls_loaded()
    print(f"  Collected {len(all_trusted_der)} qualified CA certificate(s) from TLs.\n")

    # ── Step 3: analyse each signature ──────────────────────────────────────
    for sig in sigs:
        print(f"{'─'*70}")
        print(f"Signature field : {sig['name']}")

        if "error" in sig:
            print(f"  ⚠  Error extracting signature: {sig['error']}")
            continue

        if sig["signer_cert"] is None:
            print("  ⚠  Could not extract signer certificate.")
            continue

        sc = sig["signer_cert"]
        print(f"  Signer CN      : {cert_subject_cn(sc)}")
        print(f"  Issuer         : {cert_subject_cn(sc) if False else sc.issuer.rfc4514_string()}")
        print(f"  Not before     : {sc.not_valid_before_utc}")
        print(f"  Not after      : {sc.not_valid_after_utc}")
        print(f"  Chain length   : {len(sig['chain'])} cert(s)")

        # ── Step 4: chain to trusted CA ──────────────────────────────────
        trusted_ca = chain_to_trusted_ca(sig["chain"], all_trusted_der)
        if trusted_ca:
            print(f"\n  ✅ Chains to EU Trusted List CA:")
            print(f"     CA subject : {cert_subject_cn(trusted_ca)}")
        else:
            print(f"\n  ❌ Does NOT chain to any EU Trusted List qualified CA.")

        # ── Step 5: QCStatements on signer cert ──────────────────────────
        qc = parse_qc_statements(sc)
        print(f"\n  QCStatements present : {qc['has_qc_statements']}")

        if qc["has_qc_statements"]:
            print(f"  QC Compliance        : {qc['qc_compliance']}")
            print(f"  QC SSCD              : {qc['qc_sscd']}")
            print(f"  QCType esign (natural person) : {qc['qct_esign']}")
            print(f"  QCType eseal (legal person)   : {qc['qct_eseal']}")
            print(f"  QCType web auth               : {qc['qct_web']}")
            if qc["raw_oids"]:
                print(f"  All QC OIDs          : {', '.join(qc['raw_oids'])}")

        # ── Final verdict ─────────────────────────────────────────────────
        print()
        if trusted_ca and qc["qct_esign"] and qc["qc_compliance"]:
            print("  🏆 QUALIFIED ELECTRONIC SIGNATURE — natural person (eIDAS Art. 3(12))")
        elif trusted_ca and qc["qct_eseal"] and qc["qc_compliance"]:
            print("  🏆 QUALIFIED ELECTRONIC SEAL — legal person (eIDAS Art. 3(27))")
        elif trusted_ca:
            print("  ℹ️  Chains to an EU trusted CA but lacks QCStatements for a qualified sig.")
        else:
            print("  ℹ️  Cannot confirm as a qualified signature under eIDAS.")

    print(f"\n{'='*70}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_eu_signatures.py <pdf_file>")
        sys.exit(1)

    pdf_file = sys.argv[1]
    if not Path(pdf_file).exists():
        print(f"File not found: {pdf_file}")
        sys.exit(1)

    check_pdf(pdf_file)
