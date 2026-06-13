"""
Tiny gettext-based i18n helper — no Qt dependency.
==================================================
Both the validation core and the GUI import `_` from here. English is the
source language (the literal strings in the code), so with no catalog installed
everything stays English automatically.

Translations live in:   locale/<lang>/LC_MESSAGES/sigviewer.mo
Language is chosen by (first match wins):
    1. an explicit call to install_language("cs")  (e.g. from --lang)
    2. $LANG / $LC_ALL / $LANGUAGE environment variables
    3. English fallback

Only strings wrapped in _() are translatable. We deliberately wrap just the
menu labels and the verdict strings; detail labels and stdout/stderr debug
messages are left unwrapped and therefore always English.
"""

from __future__ import annotations

import os
import gettext as _gettext
from pathlib import Path

DOMAIN = "sigviewer"
# locale/ sits next to this file, so it works from a checkout and inside the
# AppImage (where these modules live under $APPDIR/sigviewer_app/).
LOCALE_DIR = str(Path(__file__).with_name("locale"))

# Holds the active translation; starts as a null translation (English source).
_translation = _gettext.NullTranslations()


def _(message: str) -> str:
    """Translate `message` using the currently installed catalog."""
    return _translation.gettext(message)


def install_language(lang: str | None = None) -> str:
    """
    Activate a language. Returns the language actually used ("en" if none/
    fallback). Call once at startup, before building UI text.

    lang: an explicit code like "cs" or "cs_CZ" (e.g. from --lang). When None,
          fall back to the environment ($LANGUAGE/$LC_ALL/$LC_MESSAGES/$LANG).
    """
    global _translation

    if lang:
        languages = [lang]
    else:
        # Mirror gettext's env precedence; let it parse $LANG etc. itself.
        languages = None

    try:
        _translation = _gettext.translation(
            DOMAIN, localedir=LOCALE_DIR, languages=languages, fallback=True
        )
    except Exception:
        _translation = _gettext.NullTranslations()

    info = _translation.info() if hasattr(_translation, "info") else {}
    # NullTranslations (English source) has no 'language' info.
    return info.get("language", "en") if info else "en"


def available_languages() -> list[str]:
    """List language codes that have a compiled catalog under locale/."""
    base = Path(LOCALE_DIR)
    if not base.is_dir():
        return []
    langs = []
    for d in base.iterdir():
        if (d / "LC_MESSAGES" / f"{DOMAIN}.mo").exists():
            langs.append(d.name)
    return sorted(langs)
