import os
import json
import time
import datetime

class AuditManager:
    """
    Manages creation of audit records for each LLM interaction.
    """

    def __init__(self, audit_dir: str):
        self.audit_dir = audit_dir
        os.makedirs(self.audit_dir, exist_ok=True)

    def save(self, record: dict) -> None:
        """
        Saves a single audit record as a JSON file.
        The filename contains both ISO timestamp and milliseconds for uniqueness.
        """
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        unique = int(time.time() * 1000)
        filename = f"audit_{ts}_{unique}.json"
        path = os.path.join(self.audit_dir, filename)

        try:
            # Atomic write: write to temp and then replace
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            os.replace(temp_path, path)
        except Exception:
                pass