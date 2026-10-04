"""Start all four services as separate processes on localhost (ports 8000-8003).

Each service is its own process with its own key -- just like separate
machines -- and they talk over real HTTP.  Ctrl+C stops them all.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES = [
    ("a2a_auth.auth_server:create_app", 8000),
    ("a2a_auth.agents.assistant:create_app", 8001),
    ("a2a_auth.agents.calendar_agent:create_app", 8002),
    ("a2a_auth.agents.email_agent:create_app", 8003),
]

if __name__ == "__main__":
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "--factory", target,
             "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
        )
        for target, port in SERVICES
    ]
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
