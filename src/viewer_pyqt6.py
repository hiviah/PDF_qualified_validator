#!/usr/bin/env python3
"""
EU qualified signature viewer — PyQt6 executable.

Forces the PyQt6 binding, then runs the shared logic in signature_viewer_core.
All UI is in signature_viewer.ui; all logic is in signature_viewer_core.py.

    python viewer_pyqt6.py <path-to-pdf> [options]
"""
import os
os.environ.setdefault("SIGVIEWER_QT", "PyQt6")

from signature_viewer_core import main

if __name__ == "__main__":
    raise SystemExit(main())
