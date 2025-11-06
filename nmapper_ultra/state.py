# nmapper_ultra/state.py
import json
import threading
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

class ScanState:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": self.SCHEMA_VERSION, "completed": {}}
        try:
            with open(self.path) as f:
                data = json.load(f)
            if data.get("schema_version", 0) < self.SCHEMA_VERSION:
                data = self._migrate(data)
            return data
        except Exception as e:
            raise RuntimeError(f"Failed to load state: {e}")

    def _migrate(self, data: Dict) -> Dict:
        # Future migrations go here
        data["schema_version"] = self.SCHEMA_VERSION
        return data

    def _save(self):
        with open(self.path, 'w') as f:
            json.dump(self.data, f, indent=2)

    def mark_completed(self, target: str, xml_path: str):
        with self.lock:
            self.data["completed"][target] = {
                "xml": str(xml_path),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            self._save()

    def is_completed(self, target: str) -> bool:
        return target in self.data["completed"]

    def get_completed(self):
        return list(self.data["completed"].keys())
