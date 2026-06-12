# SigViewer AppImage (Option C — manylinux Python)

Builds a portable Linux AppImage of the EU qualified-signature viewer that runs
on **Ubuntu 20.04 LTS and newer**, with **no PPA and no from-source compile**.

## Why this is 20.04-compatible

`python-appimage build app` downloads the **oldest manylinux CPython** available
for the chosen version (glibc 2.17 for `manylinux2014`, or 2.28 for
`manylinux_2_28`) and pip-installs the dependencies into it. Every runtime
dependency (PyQt5, PyMuPDF, cryptography, lxml, …) ships a manylinux wheel with
its native libraries bundled, so the AppImage's glibc floor stays **below**
Ubuntu 20.04's glibc 2.31 — i.e. it runs there with margin to spare.

## Layout

```
appimage/
├── build.sh              # one-command build
├── verify-glibc.sh       # asserts the glibc floor ≤ 2.31 (gates CI)
└── SigViewer/            # python-appimage "recipe" folder
    ├── SigViewer.desktop # menu entry + PDF MIME association
    ├── SigViewer.png     # 256×256 icon
    ├── entrypoint.sh     # launches viewer_pyqt5.py from the bundled Python
    └── requirements.txt  # runtime pip deps (manylinux wheels)
```

The application sources (`check_eu_signatures.py`, `qt_compat.py`,
`signature_viewer_core.py`, `viewer_pyqt5.py`, `signature_viewer.ui`) live in the
project root and are bundled into the AppImage by `build.sh` under
`$APPDIR/sigviewer_app/`.

## Build

```bash
pip install python-appimage          # one-time
cd appimage
./build.sh                           # → SigViewer-x86_64.AppImage
PYVER=3.11 ./build.sh                # optional: pick another Python version
```

## Verify compatibility

```bash
./verify-glibc.sh SigViewer-x86_64.AppImage 2.31
```
Prints every GLIBC symbol version referenced inside the bundle and fails if any
exceeds the ceiling (default 2.31 = Ubuntu 20.04).

## Run

```bash
./SigViewer-x86_64.AppImage                 # empty window — File ▸ Open / drag a PDF
./SigViewer-x86_64.AppImage document.pdf    # open a file directly
./SigViewer-x86_64.AppImage doc.pdf --log-fetch --refresh-cache
```

The XML cache defaults to `$XDG_CACHE_HOME/sigviewer` (writable from the
read-only AppImage mount).

## Notes / gotchas

* **Qt xcb plugin** — PyQt5's wheel bundles Qt and its platform plugins, so the
  app finds them automatically. On a *very* minimal host you may still need the
  system xcb libraries (`libxcb-xinerama0`, `libxkbcommon-x11-0`, …). If you see
  `could not load the Qt platform plugin "xcb"`, run with `QT_DEBUG_PLUGINS=1`
  to see which `.so` is missing.
* **FUSE** — AppImages self-mount via libfuse2. Ubuntu 20.04 has it; on some
  newer distros run `./SigViewer-x86_64.AppImage --appimage-extract-and-run`.
* **PyQt6 variant** — to ship Qt6 instead, add `PyQt6` to `requirements.txt`,
  point `entrypoint.sh` at `viewer_pyqt6.py`, and bundle that launcher too.
* **Test on a clean target**, not the build box, e.g. a real 20.04 VM, to be
  sure nothing leaked in from the build environment.
