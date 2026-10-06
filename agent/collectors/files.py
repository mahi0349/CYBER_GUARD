import os
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

class FileSecurityCollector:
    def __init__(self, monitored_paths: Optional[List[str]] = None):
        self.monitored_paths = monitored_paths or []
        # State map: path -> (mtime, size, sha256)
        self.file_state: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self._initialized = False

    def hash_file(self, file_path: str, max_size_mb: int = 50) -> Optional[str]:
        """Calculate SHA-256 hash for relevant file without freezing on huge files."""
        try:
            if not os.path.isfile(file_path):
                return None
            size = os.path.getsize(file_path)
            if size > max_size_mb * 1024 * 1024:
                return "SKIPPED_LARGE_FILE"

            sha = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return None

    def scan_monitored_directories(self) -> List[Dict[str, Any]]:
        """
        Check monitored directories shallowly/controlled for creations, modifications, deletions.
        Generates event records.
        """
        new_events = []
        current_files: Dict[str, Dict[str, Any]] = {}

        executable_exts = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".js", ".scr", ".msi"}

        for folder in self.monitored_paths:
            if not os.path.exists(folder):
                continue
            try:
                # Scan top-level files in monitored directories (non-recursive to protect disk I/O)
                with os.scandir(folder) as it:
                    for entry in it:
                        if not entry.is_file():
                            continue
                        try:
                            stat = entry.stat()
                            f_path = entry.path
                            mtime = stat.st_mtime
                            size = stat.st_size
                            ext = os.path.splitext(entry.name)[1].lower()

                            file_info = {
                                "name": entry.name,
                                "path": f_path,
                                "size": size,
                                "mtime": mtime,
                                "is_executable": ext in executable_exts,
                                "extension": ext
                            }
                            current_files[f_path] = file_info

                            if self._initialized:
                                if f_path not in self.file_state:
                                    # File created
                                    sha = self.hash_file(f_path) if file_info["is_executable"] else None
                                    evt = {
                                        "event_type": "file_created",
                                        "filename": entry.name,
                                        "path": f_path,
                                        "size": size,
                                        "sha256": sha,
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "severity": "MEDIUM" if file_info["is_executable"] else "LOW",
                                        "details": f"New file created in {os.path.basename(folder)}"
                                    }
                                    new_events.append(evt)
                                    self.events.append(evt)
                                elif self.file_state[f_path]["mtime"] != mtime:
                                    # File modified
                                    sha = self.hash_file(f_path) if file_info["is_executable"] else None
                                    evt = {
                                        "event_type": "file_modified",
                                        "filename": entry.name,
                                        "path": f_path,
                                        "size": size,
                                        "sha256": sha,
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "severity": "LOW",
                                        "details": f"File content or metadata modified in {os.path.basename(folder)}"
                                    }
                                    new_events.append(evt)
                                    self.events.append(evt)
                        except Exception:
                            continue
            except Exception:
                continue

        # Detect deleted files
        if self._initialized:
            for old_path, old_info in list(self.file_state.items()):
                if old_path not in current_files:
                    evt = {
                        "event_type": "file_deleted",
                        "filename": old_info["name"],
                        "path": old_path,
                        "size": old_info["size"],
                        "sha256": old_info.get("sha256"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "severity": "LOW",
                        "details": "Monitored file was removed or deleted"
                    }
                    new_events.append(evt)
                    self.events.append(evt)

        # Update cached state
        self.file_state = current_files
        self._initialized = True

        # Keep event history bounded
        if len(self.events) > 100:
            self.events = self.events[-100:]

        return new_events

    def get_tracked_files(self) -> List[Dict[str, Any]]:
        """Return list of monitored files with hashes for executables."""
        results = []
        for path, info in list(self.file_state.items())[:150]:
            sha = self.hash_file(path) if info["is_executable"] else None
            results.append({
                "name": info["name"],
                "path": path,
                "size": info["size"],
                "is_executable": info["is_executable"],
                "extension": info["extension"],
                "sha256": sha,
                "last_modified": datetime.fromtimestamp(info["mtime"], tz=timezone.utc).isoformat()
            })
        return results

    def get_recent_events(self) -> List[Dict[str, Any]]:
        return list(reversed(self.events[-50:]))

file_collector = FileSecurityCollector()
