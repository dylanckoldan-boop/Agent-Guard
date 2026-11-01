"""Small operating-system helpers shared by detection, quarantine and storage."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Root-owned operating-system folders on macOS and Linux. /usr/local and /opt are left
# out on purpose: package managers such as Homebrew make them writable by the user.
POSIX_SYSTEM_DIRS = (
    "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec", "/usr/lib", "/usr/lib64",
    "/lib", "/lib64", "/boot", "/System", "/Library/Apple",
)


def windows_dir() -> str:
    """The Windows folder, asked from the system rather than read from %SystemRoot%,
    which a program running as the user can redefine for the processes it starts."""
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(260)
        n = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260)  # type: ignore[attr-defined]
        if 0 < n < 260:
            return buf.value
    except Exception:
        pass
    return r"C:\Windows"


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def is_system_path(path: str | os.PathLike[str]) -> bool:
    """True for files that belong to the operating system itself."""
    real = os.path.normcase(os.path.realpath(os.fspath(path)))
    if sys.platform == "win32":
        return _under(real, os.path.normcase(os.path.realpath(windows_dir())))
    return any(_under(real, d) for d in POSIX_SYSTEM_DIRS)


def write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically. The file is readable only by its owner
    from the moment it exists (no window in which it has default permissions)."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
