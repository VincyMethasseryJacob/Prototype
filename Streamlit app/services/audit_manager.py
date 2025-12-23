import os
import json
import time
import datetime

def filter_audit_record(record: dict) -> dict:
    """
    Filter audit record to include only required fields.
    
    Args:
        record: The complete audit record
        
    Returns:
        dict: Filtered audit record with only required fields
    """
    # Helper function to safely extract nested values
    def safe_get(data, *keys, default=None):
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data
    
    # Helper function to count CWE occurrences in a list of vulnerabilities
    def count_cwes(vuln_list):
        if not vuln_list or not isinstance(vuln_list, list):
            return 0
        cwe_set = set()
        for v in vuln_list:
            cwe_id = v.get('cwe_id') if isinstance(v, dict) else None
            if cwe_id:
                cwe_set.add(str(cwe_id))
        return len(cwe_set)
    
    # Helper function to extract unique CWEs from vulnerability list
    def extract_cwes(vuln_list):
        if not vuln_list or not isinstance(vuln_list, list):
            return []
        cwe_set = set()
        for v in vuln_list:
            cwe_id = v.get('cwe_id') if isinstance(v, dict) else None
            if cwe_id:
                cwe_set.add(str(cwe_id))
        return sorted(list(cwe_set))
    
    # Compute fix provider counts from patch data
    method_counts = {'llm-based': 0, 'rule-based': 0, 'unknown': 0}
    
    # Process initial_patch_result if it exists
    initial_patch = safe_get(record, 'initial_patch_result', default={})
    if initial_patch and initial_patch.get('changes'):
        for change in initial_patch.get('changes', []):
            method = change.get('patch_method', 'unknown')
            if method in method_counts:
                method_counts[method] += 1
            else:
                method_counts['unknown'] += 1
    
    # Process patch_iterations if they exist
    patch_iterations = safe_get(record, 'patch_iterations', default=[])
    if patch_iterations:
        for iteration in patch_iterations:
            for change in iteration.get('changes', []):
                method = change.get('patch_method', 'unknown')
                if method in method_counts:
                    method_counts[method] += 1
                else:
                    method_counts['unknown'] += 1
    
    # Extract initial detection data
    initial_run = safe_get(record, 'initial_run_by_tool', default={})
    initial_bandit_vulns = safe_get(initial_run, 'bandit', 'identified_vulnerabilities', default=[])
    initial_semgrep_vulns = safe_get(initial_run, 'semgrep', 'identified_vulnerabilities', default=[])
    initial_custom_vulns = safe_get(initial_run, 'custom_detector', 'identified_vulnerabilities', default=[])
    
    # Extract iteration detection data
    iterations = safe_get(record, 'iterations_by_tool', default={})
    iter_bandit_vulns = safe_get(iterations, 'bandit', 'identified_vulnerabilities', default=[])
    iter_semgrep_vulns = safe_get(iterations, 'semgrep', 'identified_vulnerabilities', default=[])
    iter_custom_vulns = safe_get(iterations, 'custom_detector', 'identified_vulnerabilities', default=[])
    
    # Count iterations
    patch_iterations = safe_get(record, 'patch_iterations', default=[])
    iterations_count = len(patch_iterations) if isinstance(patch_iterations, list) else 0
    
    # Extract fixed and remaining CWEs
    fixed_cwes = safe_get(record, 'fixed_cwe_ids', default=[])
    remaining_cwes = safe_get(record, 'non_fixed_cwe_ids', default=[])
    
    # Build filtered record with only required fields
    filtered = {
        # Basic information
        "workflow_id": safe_get(record, 'workflow_id', default=''),
        "workflow": safe_get(record, 'workflow', default=''),
        "timestamp": safe_get(record, 'timestamp', default=''),
        "file": safe_get(record, 'file', default=''),
        "source_file": safe_get(record, 'file', default=''),  # Using 'file' as source_file
        
        # Code content
        "original_content": safe_get(record, 'original_content', default=''),
        "llm_response": safe_get(record, 'response', default=''),
        
        # Vulnerability summary
        "vulnerabilities_found": safe_get(record, 'vulnerabilities_found', default=0),
        "total_vulnerabilities_identified": safe_get(record, 'total_vulnerabilities_identified', default=0),
        "total_vulnerabilities_fixed": safe_get(record, 'total_vulnerabilities_fixed', default=0),
        "total_vulnerabilities_remaining": safe_get(record, 'total_vulnerabilities_remaining', default=0),
        
        # Initial detection counts
        "initial_detection_bandit_count": safe_get(initial_run, 'bandit', 'count', default=0),
        "initial_detection_bandit_cwes": extract_cwes(initial_bandit_vulns),
        "initial_detection_semgrep_count": safe_get(initial_run, 'semgrep', 'count', default=0),
        "initial_detection_semgrep_cwes": extract_cwes(initial_semgrep_vulns),
        "initial_detection_ast_count": safe_get(initial_run, 'custom_detector', 'count', default=0),
        "initial_detection_ast_cwes": extract_cwes(initial_custom_vulns),
        
        # Iteration detection counts
        "iteration_detection_bandit_count": safe_get(iterations, 'bandit', 'count', default=0),
        "iteration_detection_bandit_cwes": extract_cwes(iter_bandit_vulns),
        "iteration_detection_semgrep_count": safe_get(iterations, 'semgrep', 'count', default=0),
        "iteration_detection_semgrep_cwes": extract_cwes(iter_semgrep_vulns),
        "iteration_detection_ast_count": safe_get(iterations, 'custom_detector', 'count', default=0),
        "iteration_detection_ast_cwes": extract_cwes(iter_custom_vulns),
        
        # Iteration and fix information
        "iterations_count": iterations_count,
        "fixed_cwes": fixed_cwes if isinstance(fixed_cwes, list) else [],
        "remaining_cwes": remaining_cwes if isinstance(remaining_cwes, list) else [],
        
        # Fix providers
        "fix_provider_llm": method_counts.get('llm-based', 0),
        "fix_provider_rule_based": method_counts.get('rule-based', 0),
        "fix_provider_unknown": method_counts.get('unknown', 0)
    }
    
    return filtered

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

        # Filter the record to include only required fields
        filtered_record = filter_audit_record(record)
        
        # Determine filename
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
                json.dump(filtered_record, f, ensure_ascii=False, indent=2)
            os.replace(temp_path, path)
        except Exception:
            pass
