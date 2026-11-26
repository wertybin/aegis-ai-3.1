import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Test-only local values. The published product bundles no host, port, source
# path or endpoint; these exist only so mock tests have a deterministic scope.
os.environ.setdefault("AEGIS_DEFAULT_TARGET", "http://127.0.0.1:5002")
os.environ.setdefault("AEGIS_API_BASE", "http://127.0.0.1:8765")
os.environ.setdefault("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("AEGIS_GATE_1_URL", "http://127.0.0.1:5000")
os.environ.setdefault("AEGIS_GATE_2_URL", "http://127.0.0.1:5001")
os.environ.setdefault("AEGIS_GATE_3_URL", "http://127.0.0.1:5002")
os.environ.setdefault("AEGIS_GATE_1_SOURCE", "sample_vulnerable_app/app.py")
os.environ.setdefault("AEGIS_GATE_2_SOURCE", "sample_vulnerable_app/app2.py")
os.environ.setdefault("AEGIS_GATE_3_SOURCE", "")
