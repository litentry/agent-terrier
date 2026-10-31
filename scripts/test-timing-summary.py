import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
if not path.is_file():
    print("Test report missing; this run is incomplete.")
    raise SystemExit(1)
report = json.loads(path.read_text())
print(f"Test lane: {report['lane']}; result: {'passed' if report['success'] else 'failed'}")
print(f"\nRevision: `{report['revision'] or 'local working copy; revision not asserted'}`")
print("\n| Phase | Seconds |\n|---|---:|")
for phase, duration in report["phase_seconds"].items():
    print(f"| {phase} | {duration:.3f} |")
print(f"| Measured process total | {report['seconds']:.3f} |")
print("\nQueue/setup outside this process and fixture cleanup are not separately measured.")
if report["target_exceeded"]:
    print(f"\nWarm target of {report['warm_target_seconds']} seconds exceeded; no checks were skipped to meet it.")
