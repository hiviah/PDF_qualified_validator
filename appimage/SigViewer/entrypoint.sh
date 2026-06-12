#! /bin/bash
# python-appimage substitutes {{ python-executable }} → ${APPDIR}/usr/bin/python3.x
# The application files are bundled (via -x) under ${APPDIR}/sigviewer_app/.
export SIGVIEWER_QT="${SIGVIEWER_QT:-PyQt5}"
exec "{{ python-executable }}" "${APPDIR}/sigviewer_app/viewer_pyqt5.py" "$@"
