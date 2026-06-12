#!/bin/bash
set -e
APP=SigViewer
APPDIR=$APP.AppDir
rm -rf "$APPDIR"; mkdir -p "$APPDIR/usr/share/sigviewer"
APPDIR=$(realpath $APPDIR)

# 0. Get python

#wget https://github.com/niess/python-appimage/releases/download/python3.14/python3.14.0-cp314-cp314-manylinux2014_x86_64.AppImage
#chmod +x python3.14.0-cp314-cp314-manylinux2014_x86_64.AppImage

# 1. Relocatable Python + deps into the AppDir
#./python3.14.0-cp314-cp314-manylinux2014_x86_64.AppImage -m venv "$APPDIR/usr"
python3.10 -m venv "$APPDIR/usr"
"$APPDIR/usr/bin/pip" install --upgrade pip
"$APPDIR/usr/bin/pip" install \
    PyQt5 pymupdf cryptography lxml asn1crypto requests \
    pyhanko pyhanko-certvalidator

# 2. Your application code + the shared .ui
(cd /build/src/ && \
cp check_eu_signatures.py qt_compat.py signature_viewer_core.py \
   viewer_pyqt5.py signature_viewer.ui  "$APPDIR/usr/share/sigviewer/"
)

# 3. AppRun, .desktop, icon
(cd /build/AppImageBuild/ && \
cp AppRun "$APPDIR/AppRun"; chmod +x "$APPDIR/AppRun" && \
cp sigviewer.desktop "$APPDIR/sigviewer.desktop" && \
cp sigviewer.png "$APPDIR/sigviewer.png"
)

# 4. Pack it
wget -q https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
chmod +x appimagetool-x86_64.AppImage
./appimagetool-x86_64.AppImage --appimage-extract-and-run "$APPDIR" /build/"$APP-x86_64.AppImage"
ls -l /build
