import sys
from pathlib import Path

# Make the routing_registry package importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))
