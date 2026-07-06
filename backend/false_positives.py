import json
import os
from pathlib import Path

FP_FILE = Path("data/scans/false_positives.json")

class FalsePositiveManager:
    def __init__(self):
        self.registry = self._load()
        
    def _load(self):
        if not FP_FILE.exists():
            return {}
        try:
            with open(FP_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
            
    def _save(self):
        FP_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(FP_FILE, "w") as f:
            json.dump(self.registry, f, indent=2)
            
    def _get_key(self, url: str, vulnerability_type: str) -> str:
        # A simple signature: url + type
        return f"{url}|{vulnerability_type}"

    def register(self, url: str, vulnerability_type: str):
        key = self._get_key(url, vulnerability_type)
        self.registry[key] = True
        self._save()

    def unregister(self, url: str, vulnerability_type: str):
        key = self._get_key(url, vulnerability_type)
        if key in self.registry:
            del self.registry[key]
            self._save()

    def is_false_positive(self, url: str, vulnerability_type: str) -> bool:
        key = self._get_key(url, vulnerability_type)
        return key in self.registry

fp_manager = FalsePositiveManager()
