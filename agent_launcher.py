"""
QuantumVault Endpoint Protection Agent — Local Launcher
Single-Device Windows Endpoint Security Agent
"""
import sys
import os
from pathlib import Path

# Ensure root directory is on sys.path for direct script or frozen execution
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

if __name__ == "__main__":
    from agent.main import run_agent
    run_agent()
