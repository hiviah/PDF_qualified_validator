"""
Qt binding compatibility shim
=============================
Lets the same code run on PyQt5 or PyQt6. The binding is chosen by the
environment variable SIGVIEWER_QT ("PyQt5" or "PyQt6"); if unset, PyQt6 is
preferred and PyQt5 is used as a fallback.

Everything binding-specific lives here:
  * import locations,
  * scoped (PyQt6) vs unscoped (PyQt5) enum access, exposed as plain constants,
  * QApplication.exec() vs exec_(), wrapped as app_exec(app).

Shared code imports the normalized names from this module and never touches
PyQt5/PyQt6 directly.
"""

import os

_pref = os.environ.get("SIGVIEWER_QT", "").strip().lower()


def _missing(binding: str) -> ImportError:
    return ImportError(
        f"SIGVIEWER_QT={binding} was requested but {binding} is not installed "
        f"(pip install {binding})."
    )


if _pref in ("pyqt6", "6"):
    try:
        import PyQt6  # noqa: F401
    except ImportError as e:
        raise _missing("PyQt6") from e
    BINDING = "PyQt6"
elif _pref in ("pyqt5", "5"):
    try:
        import PyQt5  # noqa: F401
    except ImportError as e:
        raise _missing("PyQt5") from e
    BINDING = "PyQt5"
else:
    # Auto-detect: prefer PyQt6, fall back to PyQt5.
    try:
        import PyQt6  # noqa: F401
        BINDING = "PyQt6"
    except ImportError:
        try:
            import PyQt5  # noqa: F401
            BINDING = "PyQt5"
        except ImportError as e:
            raise ImportError("Neither PyQt6 nor PyQt5 is installed.") from e


if BINDING == "PyQt6":
    from PyQt6 import uic
    from PyQt6.QtCore import Qt, QThread, pyqtSignal
    from PyQt6.QtGui import QImage, QPixmap
    from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel

    ALIGN_HCENTER = Qt.AlignmentFlag.AlignHCenter
    ORIENT_VERTICAL = Qt.Orientation.Vertical
    FORMAT_RGB888 = QImage.Format.Format_RGB888

    def app_exec(app):
        return app.exec()

else:  # PyQt5
    from PyQt5 import uic
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QImage, QPixmap
    from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

    ALIGN_HCENTER = Qt.AlignHCenter
    ORIENT_VERTICAL = Qt.Vertical
    FORMAT_RGB888 = QImage.Format_RGB888

    def app_exec(app):
        return app.exec_()


__all__ = [
    "BINDING", "uic", "Qt", "QThread", "pyqtSignal", "QImage", "QPixmap",
    "QApplication", "QMainWindow", "QLabel",
    "ALIGN_HCENTER", "ORIENT_VERTICAL", "FORMAT_RGB888", "app_exec",
]
