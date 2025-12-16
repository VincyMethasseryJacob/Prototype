import os
import json
import time
import datetime

class AuditManager:
    """
    Manages creation of audit records for each LLM interaction.
    Organizes audits into timestamped session folders.
    """

    def __init__(self, audit_dir: str, session_state=None):
        self.audit_dir = audit_dir
        self.session_state = session_state
        self.session_folder = None
        self.workflow_type = None
        os.makedirs(self.audit_dir, exist_ok=True)

    def set_session_folder(self, force_new: bool = False, workflow_type: str = None, file_identifier: str = None) -> str:
        """
        Creates a new timestamped session folder for organizing related audit records.
        Subsequent saves will go into this folder until a new session is created.
        
        Args:
            force_new: If True, always creates a new folder. If False, returns existing folder if available.
            workflow_type: Type of workflow ('manual_prompt' or 'dataset_prompt')
            file_identifier: For dataset_prompt, the file identifier (e.g., 'CWE-020_author_1')
        
        Returns:
            str: Path to the created session folder
        """
        # Store workflow type if provided
        if workflow_type:
            self.workflow_type = workflow_type
            if self.session_state is not None:
                self.session_state["workflow_type"] = workflow_type
        
        # If not forcing new and a session folder already exists, return it
        if not force_new:
            if self.session_state is not None and "audit_session_folder" in self.session_state:
                existing_folder = self.session_state["audit_session_folder"]
                if existing_folder and os.path.exists(existing_folder):
                    self.session_folder = existing_folder
                    return existing_folder
        
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Include file identifier for dataset_prompt, or workflow_type for manual_prompt
        if file_identifier:
            workflow_suffix = f"_{file_identifier}"
        elif workflow_type == 'manual_prompt':
            workflow_suffix = f"_{workflow_type}"
        else:
            workflow_suffix = ""
        session_folder_name = f"{timestamp}{workflow_suffix}"
        session_path = os.path.join(self.audit_dir, session_folder_name)
        
        # If folder already exists (same second), add milliseconds to make it unique
        if os.path.exists(session_path):
            ms = int((time.time() * 1000) % 1000)
            session_folder_name = f"{timestamp}_{ms}"
            session_path = os.path.join(self.audit_dir, session_folder_name)
        
        os.makedirs(session_path, exist_ok=True)
        self.session_folder = session_path
        
        # Store in session state if available
        if self.session_state is not None:
            self.session_state["audit_session_folder"] = session_path
        
        return session_path

    def get_session_folder(self) -> str:
        """
        Returns the current session folder path.
        Creates one if none exists.
        
        Returns:
            str: Path to the current session folder
        """
        # Check session state first
        if self.session_state is not None and "audit_session_folder" in self.session_state:
            existing_folder = self.session_state["audit_session_folder"]
            if existing_folder and os.path.exists(existing_folder):
                self.session_folder = existing_folder
                return self.session_folder
        
        # Check instance variable
        if self.session_folder is not None and os.path.exists(self.session_folder):
            return self.session_folder
        
        # Create new session folder if none exists
        return self.set_session_folder()

    def save(self, record: dict, workflow_id: str = None, use_audit_prefix: bool = False) -> None:
        """
        Saves a single audit record as a JSON file in the current session folder.
        The filename uses workflow_id or audit_prefix format based on workflow type.
        If no session folder is set, creates one automatically.
        
        Args:
            record: The audit record to save
            workflow_id: Optional workflow ID to use as base for filename
            use_audit_prefix: If True, use 'audit_YYYYMMDD_HHMMSS.json' format
        """
        # If no session folder is set, create one
        if self.session_folder is None:
            self.get_session_folder()

        # --- Ensure 'fixed_by' key is present in each tool section ---
        def ensure_fixed_by(tool_dict, fix_technique_summary):
            # Map each CWE to its specific fix technique if available
            fixed_by = []
            if tool_dict.get('identified_vulnerabilities'):
                for v in tool_dict['identified_vulnerabilities']:
                    cwe_id = v.get('cwe_id')
                    fix_type = ''
                    # If fix_technique_summary is a dict mapping CWE IDs to fix techniques
                    if fix_technique_summary:
                        # Try to get fix technique for this CWE
                        if isinstance(fix_technique_summary, dict):
                            fix_type = fix_technique_summary.get(str(cwe_id), '')
                            # If not found, try as int
                            if not fix_type and cwe_id is not None:
                                fix_type = fix_technique_summary.get(int(cwe_id), '') if str(cwe_id).isdigit() else ''
                        else:
                            fix_type = str(fix_technique_summary)
                    if not fix_type:
                        fix_type = 'unknown'
                    fixed_by.append({"cwe_id": cwe_id, "fix": fix_type})
            tool_dict['fixed_by'] = fixed_by

        fix_technique_summary = record.get('fix_technique_summary', {})
        # Initial run
        if 'initial_run_by_tool' in record:
            for tool in record['initial_run_by_tool'].values():
                if 'fixed_by' not in tool:
                    ensure_fixed_by(tool, fix_technique_summary)
        # Iterations
        if 'iterations_by_tool' in record:
            for tool in record['iterations_by_tool'].values():
                if 'fixed_by' not in tool:
                    ensure_fixed_by(tool, fix_technique_summary)

        # Use audit_prefix format if specified (for dataset_prompt)
        if use_audit_prefix:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"audit_{ts}.json"
        elif workflow_id:
            filename = f"{workflow_id}.json"
        else:
            ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            unique = int(time.time() * 1000)
            filename = f"audit_{ts}_{unique}.json"
        
        path = os.path.join(self.session_folder, filename)

        try:
            # Atomic write: write to temp and then replace
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            os.replace(temp_path, path)
        except Exception:
            pass
