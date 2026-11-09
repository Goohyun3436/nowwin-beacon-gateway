#!/usr/bin/env python3
"""Poll source, rebuild and restart on edits. Keep the last good process on compile errors."""
import pathlib, subprocess, time, signal
root = pathlib.Path(__file__).resolve().parents[1]
process = None
previous = None
try:
    while True:
        current = {str(p): p.stat().st_mtime_ns for p in root.rglob('*') if p.suffix in ('.go', '.html')}
        if current != previous:
            previous = current
            result = subprocess.run(['go', 'build', '-o', '.scanner-next', './cmd/server'], cwd=root)
            if result.returncode == 0:
                if process:
                    process.send_signal(signal.SIGINT)
                    process.wait(timeout=10)
                (root / '.scanner-next').replace(root / '.scanner')
                process = subprocess.Popen([str(root / '.scanner')], cwd=root)
        time.sleep(.5)
except KeyboardInterrupt:
    pass
finally:
    if process:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
