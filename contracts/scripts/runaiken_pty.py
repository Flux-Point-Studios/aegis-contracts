"""Run aiken check inside a real pty (ConPTY-backed) to capture the diagnostic.

Aiken writes its rendered errors via a TTY-detecting code path; subprocess pipes
defeat that detection on Windows. We use the `pywinpty` library if available;
otherwise fall back to allocating a console via `pyte` or just dumping the JSON
output (which IS captured).
"""
import json
import os
import subprocess
import sys

# Strategy 1: try pywinpty
try:
    import winpty  # noqa: F401
    HAVE_WINPTY = True
except ImportError:
    HAVE_WINPTY = False

if HAVE_WINPTY:
    import winpty
    args = sys.argv[1:] if len(sys.argv) > 1 else ["check"]
    pty = winpty.PtyProcess.spawn(
        ["cmd.exe", "/c", "aiken.exe"] + args,
        cwd=r"D:\aegis-contracts\contracts",
        dimensions=(50, 200),
    )
    out_chunks = []
    while True:
        try:
            chunk = pty.read()
        except (EOFError, winpty.WinptyError):
            break
        if not chunk:
            break
        out_chunks.append(chunk)
    pty.wait()
    raw = "".join(out_chunks)
    # Strip ANSI escape sequences for easier reading.
    import re
    ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b\(B|\x1b=|\x1b>|\x1b\[\?[0-9]+[hl]")
    osc_re = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
    cleaned = ansi_re.sub("", osc_re.sub("", raw))
    cleaned = re.sub(r"\x1b\[\?[0-9]+[hl]", "", cleaned)
    cleaned = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", cleaned)
    cleaned = re.sub(r"]8;;[^\\]*\\", "", cleaned)
    cleaned = re.sub(r"\x07", "", cleaned)
    with open(r"D:\aegis-contracts\contracts\aiken_check.log", "w", encoding="utf-8") as fh:
        fh.write(cleaned)
        fh.write(f"\n=== EXIT: {pty.exitstatus} ===\n")
    print(f"=== EXIT: {pty.exitstatus} ===  [{len(raw)} bytes raw / {len(cleaned)} cleaned -> aiken_check.log]")
    sys.exit(pty.exitstatus or 0)
else:
    print("pywinpty not available", file=sys.stderr)
    sys.exit(2)
