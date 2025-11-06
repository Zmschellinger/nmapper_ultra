# nmapper_ultra/nmapper_ultra/__init__.py
__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"

# Optional: expose top-level API
from .cli import app
from .state import ScanState
from .scanner import NmapBuilder

__all__ = [
    "app",
    "ScanState",
    "NmapBuilder",
]
