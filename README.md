# PDF signature validator for PDFs with EU's qualified signatures

## Overview

This program takes main argument, a PDF file.

Checks all signatures extracted from PDF against whether they are valid, whether
they chain to the qualified CAs obtained from EU LOTL and national TLs.

Checks `QcStatements` so that we know the signer certificate is qualified (person, seal...).

Outputs signatures - CN of signer - and result for each signature:

  * signature is consistent, not broken due to bad data
  * signature chains to a known root
  * such CA root belongs among the EU qualified signature roots (person, seal, web is recognized now)
  * shows other OIDs found under the QcStatements extension

## Install:

Python >= 3.10 is required.

Install venv and add `requirements.txt` according to file:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Example run (in the virtualenv):

python3 --hard-revocation MySigned.pdf
