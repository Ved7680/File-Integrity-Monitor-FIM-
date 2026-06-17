"""Small cross-cutting helpers shared by other FIM modules."""

import sys

def clean_path(p: str) -> str:
    """Strip surrounding single/double quotes from a path argument.

    Windows ``cmd.exe`` doesn't strip these the way POSIX shells do,
    so user-supplied paths can arrive with literal quote characters.
    """
    if not isinstance(p, str):
        return p
    s = p.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    return s


def enable_utf8_stdout() -> None:
    """Reconfigure stdout/stderr to UTF-8 (no-op if already UTF-8).

    Needed on Windows where the default ``cp1252`` console can't render
    the Unicode glyphs used throughout the FIM CLI output.
    """
    for stream_name in ('stdout', 'stderr'):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                pass
