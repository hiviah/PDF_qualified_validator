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

#: Preferred binding from the SIGVIEWER_QT env var ("pyqt5"/"pyqt6"/""=auto).
_pref = os.environ.get("SIGVIEWER_QT", "").strip().lower()


def _missing(binding: str) -> ImportError:
    """Return an ``ImportError`` describing a missing, explicitly-requested binding.

    Args:
        binding: the binding name, ``"PyQt5"`` or ``"PyQt6"``.
    """
    return ImportError(
        f"SIGVIEWER_QT={binding} was requested but {binding} is not installed "
        f"(pip install {binding})."
    )


if _pref in ("pyqt6", "6"):
    try:
        import PyQt6  # noqa: F401
    except ImportError as e:
        raise _missing("PyQt6") from e
    BINDING = "PyQt6"   #: the Qt binding actually in use ("PyQt5" or "PyQt6")
elif _pref in ("pyqt5", "5"):
    try:
        import PyQt5  # noqa: F401
    except ImportError as e:
        raise _missing("PyQt5") from e
    BINDING = "PyQt5"   #: the Qt binding actually in use ("PyQt5" or "PyQt6")
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
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QByteArray
    from PyQt6.QtGui import (
        QImage, QPixmap, QFont, QTextCursor, QTextCharFormat,
        QStandardItemModel, QStandardItem,
    )
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QLabel, QFileDialog, QMessageBox,
    )

    # Normalized constants (scoped enums differ between PyQt5/PyQt6):
    ALIGN_HCENTER = Qt.AlignmentFlag.AlignHCenter   #: horizontal-center alignment flag
    ORIENT_VERTICAL = Qt.Orientation.Vertical       #: vertical orientation (resizeDocks)
    FORMAT_RGB888 = QImage.Format.Format_RGB888      #: 24-bit RGB QImage format
    FONT_BOLD = QFont.Weight.Bold                    #: bold font weight
    KEEP_ANCHOR = QTextCursor.MoveMode.KeepAnchor    #: extend selection while moving a cursor

    def app_exec(app):
        """Run the Qt event loop for ``app`` (PyQt6 uses ``exec()``)."""
        return app.exec()

else:  # PyQt5
    from PyQt5 import uic
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QByteArray
    from PyQt5.QtGui import (
        QImage, QPixmap, QFont, QTextCursor, QTextCharFormat,
        QStandardItemModel, QStandardItem,
    )
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QLabel, QFileDialog, QMessageBox,
    )

    # Normalized constants (same names as the PyQt6 branch above):
    ALIGN_HCENTER = Qt.AlignHCenter      #: horizontal-center alignment flag
    ORIENT_VERTICAL = Qt.Vertical        #: vertical orientation (resizeDocks)
    FORMAT_RGB888 = QImage.Format_RGB888  #: 24-bit RGB QImage format
    FONT_BOLD = QFont.Bold               #: bold font weight
    KEEP_ANCHOR = QTextCursor.KeepAnchor  #: extend selection while moving a cursor

    def app_exec(app):
        """Run the Qt event loop for ``app`` (PyQt5 uses ``exec_()``)."""
        return app.exec_()


#: public names re-exported for the rest of the app (binding-agnostic).
__all__ = [
    "BINDING", "uic", "Qt", "QThread", "pyqtSignal", "QByteArray",
    "QImage", "QPixmap", "QFont", "QTextCursor", "QTextCharFormat",
    "QStandardItemModel", "QStandardItem",
    "QApplication", "QMainWindow", "QLabel", "QFileDialog", "QMessageBox",
    "ALIGN_HCENTER", "ORIENT_VERTICAL", "FORMAT_RGB888", "FONT_BOLD",
    "KEEP_ANCHOR", "app_exec",
]
