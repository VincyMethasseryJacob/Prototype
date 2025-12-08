import os
import re
import sys
import datetime
import pandas as pd
import streamlit as st
from services import (
    SecurityEvalLoader,
    CWEFetcher,
    AuditManager,
    OpenAIClientWrapper,
)
from ui_templates import (
    get_app_header,
    get_input_mode_header,
    get_example_prompts,
    get_prompt_count_text,
    get_analysis_header,
    get_api_key_screen,
    get_dropdown_width_style,
    get_section_header,
    get_code_block_style,
)

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from backend.workflow import VulnerabilityAnalysisWorkflow

# Directories
TESTCASES_DIR = r"D:\Vincy-Certificates\AIDA\Winter'25\Thesis\Prototype\SecurityEval-main\Testcases_Prompt"
AUDIT_DIR = os.path.join(os.path.dirname(__file__), "audit_records")
VULNERABLE_SAMPLES_DIR = r"D:\Vincy-Certificates\AIDA\Winter'25\Thesis\Prototype\Author_Insecure_Code"
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

# Limits
MAX_PROMPTS = 20
MAX_RESPONSE_TOKENS = 5000


def _add_line_numbers(code: str) -> str:
    """Return code with 1-based line numbers for display."""
    numbered_lines = []
    for idx, line in enumerate(code.split('\n'), 1):
        numbered_lines.append(f"{idx:4}: {line}")
    return "\n".join(numbered_lines)


def parse_cwe_info(cwe_data: str) -> tuple:
    """
    Parse CWE information to extract ID and name.
    Handles formats like:
    - "78" -> ("CWE-078", "OS Command Injection")
    - "78: OS Command Injection" -> ("CWE-078", "OS Command Injection")
    - "CWE-078" -> ("CWE-078", "OS Command Injection")
    
    Returns:
        tuple: (formatted_cwe_id, cwe_name)
    """
    if not cwe_data or cwe_data == 'N/A':
        return ('N/A', '')
    
    cwe_str = str(cwe_data).strip()
    
    # Check if there's a colon separating ID from name
    if ':' in cwe_str:
        parts = cwe_str.split(':', 1)
        cwe_id = parts[0].strip()
        cwe_name = parts[1].strip()
    else:
        cwe_id = cwe_str
        cwe_name = ''
    
    # Extract just the number from formats like "CWE-78" or "78"
    cwe_id = re.sub(r'[^\d]', '', cwe_id)
    
    # Format as CWE- with zero-padding to 3 digits
    if cwe_id and cwe_id.isdigit():
        formatted_cwe = f"CWE-{int(cwe_id):03d}"
        # If no name was provided, fetch it from the mapping
        if not cwe_name:
            cwe_name = get_cwe_name(cwe_id)
    else:
        formatted_cwe = 'N/A'
    
    return (formatted_cwe, cwe_name)


def get_cwe_name(cwe_id: str) -> str:
    """
    Get CWE name from CWE ID using the mapping from VulnerabilityDetector.
    """
    # Normalize CWE ID - remove 'CWE-' prefix if present
    cwe_id_str = str(cwe_id).strip()
    if cwe_id_str.upper().startswith('CWE-'):
        cwe_id_str = cwe_id_str[4:]
    
    # Pad with leading zeros for consistency
    if cwe_id_str.isdigit() and len(cwe_id_str) < 3:
        cwe_id_str = cwe_id_str.zfill(3)
    
    cwe_names = {
        '020': 'Improper Input Validation',
        '022': 'Path Traversal',
        '078': 'OS Command Injection',
        '080': 'Improper Neutralization of Script-Related HTML Tags (Basic XSS)',
        '089': 'SQL Injection',
        '094': 'Code Injection',
        '095': 'Eval Injection',
        '116': 'Improper Encoding',
        '117': 'Log Injection',
        '193': 'Off-by-one Error',
        '200': 'Information Exposure',
        '252': 'Unchecked Return Value',
        '259': 'Hard-coded Password',
        '285': 'Improper Authorization',
        '295': 'Certificate Validation',
        '319': 'Cleartext Transmission',
        '321': 'Hard-coded Cryptographic Key',
        '326': 'Weak Encryption',
        '330': 'Weak Random',
        '331': 'Insufficient Entropy',
        '352': 'Cross-Site Request Forgery (CSRF)',
        '367': 'TOCTOU Race Condition',
        '377': 'Insecure Temporary File',
        '400': 'Uncontrolled Resource Consumption',
        '414': 'Missing Lock Check',
        '425': 'Direct Request',
        '454': 'External Initialization',
        '477': 'Obsolete Function',
        '502': 'Deserialization',
        '522': 'Insufficiently Protected Credentials',
        '532': 'Insertion of Sensitive Information into Log File',
        '595': 'Sensitive Cookie',
        '605': 'Multiple Binds',
        '611': 'XXE',
        '614': 'Sensitive Cookie in HTTPS Session',
        '693': 'Missing Security Header',
        '703': 'Improper Check',
        '730': 'Regex DoS',
        '732': 'Incorrect Permission',
        '798': 'Hard-coded Credentials',
        '835': 'Infinite Loop',
        '937': 'Using Components with Known Vulnerabilities',
        '1004': 'Sensitive Cookie Without Secure Flag'
    }
    return cwe_names.get(cwe_id_str, 'Unknown Vulnerability')


def get_code_context(code: str, line_number: int, context_lines: int = 2) -> str:
    """
    Extract code context around a specific line with an arrow pointing to the issue.
    
    Args:
        code: The full source code
        line_number: The line number where the issue occurs (1-indexed)
        context_lines: Number of lines to show before and after the issue line
        
    Returns:
        Formatted string with code context and arrow
    """
    lines = code.split('\n')
    total_lines = len(lines)
    
    # Calculate range (convert to 0-indexed)
    start_line = max(0, line_number - 1 - context_lines)
    end_line = min(total_lines, line_number + context_lines)
    
    # Build the context string
    context_parts = []
    for i in range(start_line, end_line):
        line_num = i + 1
        line_content = lines[i] if i < len(lines) else ""
        
        if line_num == line_number:
            # Add arrow for the issue line
            context_parts.append(f"→ {line_num:>3}: {line_content}")
        else:
            context_parts.append(f"  {line_num:>3}: {line_content}")
    
    return '\n'.join(context_parts)


def get_code_from_iteration_file(iteration_file_path: str, line_number: int, context_lines: int = 2) -> str:
    """
    Read code context from an iteration file.
    
    Args:
        iteration_file_path: Path to the iteration code file
        line_number: The line number where the issue occurs (1-indexed)
        context_lines: Number of lines to show before and after the issue line
        
    Returns:
        Formatted string with code context and arrow, or empty string if file not found
    """
    try:
        if os.path.exists(iteration_file_path):
            with open(iteration_file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return get_code_context(code, line_number, context_lines)
        else:
            return ""
    except Exception as e:
        st.warning(f"Could not read iteration file: {str(e)}")
        return ""


class App:
    def __init__(self):
        st.set_page_config(
            page_title="LLM-CVAM Framework",
            layout="wide",
            initial_sidebar_state="collapsed",
        )

        self._ensure_session()

        self.loader = SecurityEvalLoader()
        self.cwe = CWEFetcher()
        self.audit = AuditManager(AUDIT_DIR)
        self.client_wrapper = None
        self.workflow = None

        if st.session_state.get("api_loaded") and st.session_state.get("api_key"):
            try:
                self.client_wrapper = OpenAIClientWrapper(st.session_state["api_key"])
                # Initialize workflow with OpenAI client for LLM-based patching
                self.workflow = VulnerabilityAnalysisWorkflow(
                    vulnerable_samples_dir=VULNERABLE_SAMPLES_DIR,
                    reports_dir=REPORTS_DIR,
                    openai_client=self.client_wrapper,
                    max_patch_iterations=6
                )
                st.session_state.api_init_error = ""
            except Exception as e:
                st.session_state.api_loaded = False
                st.session_state.api_init_error = str(e)
                self.client_wrapper = None
                self.workflow = None

    def _ensure_session(self):
        defaults = {
            "api_loaded": False,
            "api_key": "",
            "api_init_error": "",
            "securityeval_map": {},
            "prompt_count": 0,
            "active_prompt": "",
            "manual_prompt_text": "",
            "last_generated_code": "",
            "last_workflow_result": None,
            "show_analysis_view": False,
        }
        for k, v in defaults.items():
            if k not in st.session_state:
                st.session_state[k] = v

    # -------------------- API KEY SCREEN --------------------
    def render_api_input(self):
        # If API already loaded, skip this screen
        if st.session_state.api_loaded:
            return

        if st.session_state.get("api_init_error"):
            st.error(f"Failed to initialize: {st.session_state.api_init_error}")

        with st.container():
            st.markdown(get_api_key_screen(), unsafe_allow_html=True)

            # Centered, slightly narrower API input and small button
            col_left, col_center, col_right = st.columns([0.35, 0.3, 0.35])
            with col_center:
                api_key = st.text_input("OpenAI API Key", type="password")
                st.write("")  
                if st.button("Load Application"):
                    if not api_key.strip():
                        st.error("Please enter a valid API key.")
                        return
                    # Validate API key with OpenAI
                    from services.openai_client_wrapper import OpenAIClientWrapper
                    if not OpenAIClientWrapper.validate_api_key(api_key.strip()):
                        st.error("The entered API key is invalid. Please check and try again.")
                        return
                    st.session_state.api_key = api_key.strip()
                    st.session_state.api_loaded = True
                    st.session_state.securityeval_map = self.loader.load_prompts(TESTCASES_DIR)
                    st.session_state.api_init_error = ""
                    st.success("API key validated! Loading application…")
                    st.rerun()

        # Stop rendering below until API is loaded
        st.stop()

    # -------------------- MAIN UI --------------------
    def render_main_ui(self):
        if not self.client_wrapper:
            try:
                self.client_wrapper = OpenAIClientWrapper(st.session_state.api_key)
            except Exception as e:
                st.error(f"OpenAI init error: {e}")
                st.stop()

        # If there's no current generated code, ensure analysis view is off
        if not st.session_state.get("last_generated_code"):
            st.session_state.show_analysis_view = False

        # If we have analysis results with vulnerabilities, show analysis view
        if st.session_state.get("show_analysis_view") and st.session_state.get("last_workflow_result"):
            self._render_analysis_page()
            return

        # Top: Centered title and description
        st.markdown(get_app_header(), unsafe_allow_html=True)
        # Spacing after header
        st.markdown("<div style='margin: 35px 0;'></div>", unsafe_allow_html=True)

        # Main layout: 3 columns with vertical dividers, adjusted widths
        col1, col2, col3 = st.columns([0.15, 0.57, 0.28], gap="medium")

        # Sidebar: always visible
        with col1:
            st.markdown(get_input_mode_header(), unsafe_allow_html=True)
            option = st.radio(
                "",
                ("Enter new prompt", "Choose from dataset"),
                horizontal=False,
                label_visibility="collapsed"
            )
        
        # Clear session state when switching between input modes
        if "last_input_mode" not in st.session_state:
            st.session_state.last_input_mode = option
        elif st.session_state.last_input_mode != option:
            st.session_state.last_input_mode = option
            st.session_state.last_generated_code = None
            st.session_state.last_workflow_result = None
            st.session_state.show_analysis_view = False
            st.session_state.active_prompt = ""

        # Center: dropdown and prompt box
        with col2:
            if option == "Enter new prompt":
                self._ui_new_prompt(wide=True)
            else:
                self._ui_dataset_prompt(wide=True)
            st.markdown(
                get_prompt_count_text(st.session_state.prompt_count, MAX_PROMPTS),
                unsafe_allow_html=True,
            )

        # Right: example prompts (only for manual entry mode)
        with col3:
            if option == "Enter new prompt":
                st.markdown(get_section_header("Example Prompts"), unsafe_allow_html=True)
                st.markdown(get_example_prompts(), unsafe_allow_html=True)

    # -------------------- NEW PROMPT UI --------------------
    def _ui_new_prompt(self, wide=False):
        prompt = st.text_area(
            "Enter the prompt (Python code tasks only):",
            height=300,
            key="manual_prompt_text",
            label_visibility="visible",
        )
        colA, colB = st.columns([0.2, 0.8])
        with colA:
            generate_clicked = st.button("Generate", key="manual_generate_btn")
        
        if generate_clicked:
            prompt_text = st.session_state.get("manual_prompt_text", "").strip()
            if st.session_state.prompt_count >= MAX_PROMPTS:
                st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
                st.warning("Maximum prompts reached (20).")
            elif not prompt_text:
                st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
                st.warning("Prompt cannot be empty.")
            else:
                with st.spinner("Generating code from LLM..."):
                    generated_code = self.client_wrapper.generate_code_only_response(
                        prompt_text, max_tokens=MAX_RESPONSE_TOKENS
                    )
                st.session_state.active_prompt = prompt_text
                st.session_state.prompt_count += 1
                st.session_state.last_generated_code = generated_code
        
        # Display generated code outside column context for full width
        if st.session_state.get("last_generated_code") and st.session_state.get("active_prompt"):
            st.markdown("### Generated Code")
            st.markdown("<style>div[data-testid='stCodeBlock']{width:100% !important; max-width:100% !important;}</style>", unsafe_allow_html=True)
            st.code(st.session_state.last_generated_code, language="python")
        if st.session_state.get("last_generated_code"):
            # Smaller left-aligned analyze button
            colAnalyze, _ = st.columns([0.25, 0.75])
            with colAnalyze:
                analyze_clicked = st.button("Analyze Vulnerabilities", key="manual_analyze_btn")
            
            if analyze_clicked:
                if not st.session_state.get("last_generated_code"):
                    st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
                    st.warning("Generate code before analyzing.")
                else:
                    with st.spinner("Running vulnerability analysis..."):
                        workflow_result = self.workflow.run_complete_workflow(
                            st.session_state.last_generated_code,
                            prompt=st.session_state.get("active_prompt", "")
                        )
                        st.session_state.last_workflow_result = workflow_result
                    self.audit.save(
                        {
                            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                            "workflow": "new_prompt",
                            "prompt": st.session_state.get("active_prompt", ""),
                            "response": st.session_state.last_generated_code,
                            "prompt_count": st.session_state.prompt_count,
                            "vulnerabilities_found": workflow_result.get('vulnerability_count', 0),
                            "workflow_id": workflow_result.get('workflow_id')
                        }
                    )
                    # Only show analysis view if vulnerabilities found by any tool
                    custom_count = workflow_result.get('vulnerability_count', 0)
                    bandit_count = len(workflow_result.get('bandit_original', {}).get('issues', []))
                    semgrep_count = len(workflow_result.get('semgrep_original', {}).get('issues', []))
                    total_vulns = custom_count + bandit_count + semgrep_count
                    
                    if total_vulns > 0:
                        st.session_state.show_analysis_view = True
                    st.rerun()
            
            # Display results if analysis was run but no vulnerabilities found (staying on same page)
            if st.session_state.get("last_workflow_result") and not st.session_state.get("show_analysis_view"):
                self._display_workflow_results(st.session_state.last_workflow_result)

    # -------------------- DATASET UI --------------------
    def _ui_dataset_prompt(self, wide=False):
        mp = st.session_state.securityeval_map
        if not mp:
            st.info("Dataset folder is empty.")
            return
        selected = st.selectbox("Select sample:", list(mp.keys()), key="dataset_select")
        
        # Track dataset selection changes and clear state when different sample is selected
        if "last_selected_dataset" not in st.session_state:
            st.session_state.last_selected_dataset = selected
        elif st.session_state.last_selected_dataset != selected:
            # Clear previous results when selecting a different dataset sample
            st.session_state.last_selected_dataset = selected
            st.session_state.last_generated_code = None
            st.session_state.last_workflow_result = None
            st.session_state.show_analysis_view = False
            st.session_state.active_prompt = ""
        
        st.markdown(get_dropdown_width_style(230), unsafe_allow_html=True)
        entry = mp[selected]
        content = entry["content"]
        # Show code immediately on selection
        st.markdown("<div style='font-size:1.1em; font-weight:600; margin-bottom:8px;'>Sample Code</div>", unsafe_allow_html=True)
        st.markdown(get_code_block_style(), unsafe_allow_html=True)
        st.code(content, language="python")
        # Generate button, small and left-aligned
        colA, colB = st.columns([0.2, 0.8])
        with colA:
            generate_clicked = st.button("Generate", key="dataset_generate_btn")
        
        if generate_clicked:
            if st.session_state.prompt_count >= MAX_PROMPTS:
                st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
                st.warning("Maximum prompts reached (20).")
            else:
                text = self.client_wrapper.generate_code_only_response(
                    content,
                    max_tokens=MAX_RESPONSE_TOKENS,
                    allow_non_code_prompt=True,
                    enforce_input_limit=False
                )
                st.session_state.prompt_count += 1
                st.session_state.last_generated_code = text
                st.session_state.active_prompt = f"Dataset: {selected}"
                self.audit.save(
                    {
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "workflow": "dataset_prompt",
                        "file": selected,
                        "content": content,
                        "response": text,
                        "prompt_count": st.session_state.prompt_count,
                    }
                )
        
        # Display generated code outside column context for full width
        if st.session_state.get("last_generated_code") and st.session_state.get("active_prompt", "").startswith("Dataset:"):
            st.markdown("### Generated Code")
            st.markdown("<style>div[data-testid='stCodeBlock']{width:100% !important; max-width:100% !important;}</style>", unsafe_allow_html=True)
            st.code(st.session_state.last_generated_code, language="python")
        if st.session_state.get("last_generated_code"):
            # Smaller left-aligned analyze button for dataset flow
            colAnalyze, _ = st.columns([0.50, 0.50])
            with colAnalyze:
                analyze_clicked = st.button("Analyze Vulnerabilities", key="dataset_analyze_btn")
            
            if analyze_clicked:
                if not st.session_state.get("last_generated_code"):
                    st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
                    st.warning("Generate code before analyzing.")
                else:
                    with st.spinner("Running vulnerability analysis..."):
                        workflow_result = self.workflow.run_complete_workflow(
                            st.session_state.last_generated_code,
                            prompt=st.session_state.get("active_prompt", "")
                        )
                        st.session_state.last_workflow_result = workflow_result
                    self.audit.save(
                        {
                            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                            "workflow": "dataset_prompt_analysis",
                            "file": selected,
                            "content": content,
                            "response": st.session_state.last_generated_code,
                            "prompt_count": st.session_state.prompt_count,
                            "vulnerabilities_found": workflow_result.get('vulnerability_count', 0),
                            "workflow_id": workflow_result.get('workflow_id')
                        }
                    )
                    # Only show analysis view if vulnerabilities found by any tool
                    custom_count = workflow_result.get('vulnerability_count', 0)
                    bandit_count = len(workflow_result.get('bandit_original', {}).get('issues', []))
                    semgrep_count = len(workflow_result.get('semgrep_original', {}).get('issues', []))
                    total_vulns = custom_count + bandit_count + semgrep_count
                    
                    if total_vulns > 0:
                        st.session_state.show_analysis_view = True
                    st.rerun()
            
            # Display results if analysis was run but no vulnerabilities found (staying on same page)
            if st.session_state.get("last_workflow_result") and not st.session_state.get("show_analysis_view"):
                self._display_workflow_results(st.session_state.last_workflow_result)

    # -------------------- UTIL --------------------
    @staticmethod
    def _extract_short_description(content: str) -> str:
        lines = content.splitlines()
        desc = []
        for ln in lines:
            s = ln.strip()
            if s.startswith("#"):
                desc.append(s.lstrip("# ").rstrip())
            elif desc:
                break
            elif not s:
                continue
            else:
                break
        if desc:
            return " ".join(desc[:6])

        for ln in lines[:40]:
            if "CWE" in ln.upper():
                return ln.strip()

        return "No short description found."
    
    def _render_analysis_page(self):
        """Render dedicated analysis results page without prompt interface."""
        results = st.session_state.get("last_workflow_result", {})
        
        # Header with back button
        col1, col2, col3 = st.columns([0.15, 0.7, 0.15])
        with col1:
            if st.button("← New Analysis", use_container_width=True):
                st.session_state.show_analysis_view = False
                st.session_state.last_generated_code = ""
                st.session_state.last_workflow_result = None
                st.rerun()
        
        with col2:
            st.markdown(get_analysis_header(), unsafe_allow_html=True)
        
        # Display the full workflow results
        self._display_workflow_results(results)
    
    def _display_workflow_results(self, results: dict):
        """Display workflow results in Streamlit UI."""
        # Full-width horizontal line
        st.markdown("<hr style='width:100%; margin: 20px 0; border: none; border-top: 1px solid #ddd;'>", unsafe_allow_html=True)
        
        # Smaller heading when shown inline; larger on dedicated analysis page
        if st.session_state.get("show_analysis_view"):
            st.markdown("## 🔍 LLM Vulnerability Analysis Results")
        else:
            st.markdown("### 🔍 LLM Vulnerability Analysis Results")
        
        # Status badge
        status = results.get('status', 'unknown')
        if status == 'clean':
            st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
            st.success("✅ No vulnerabilities detected - code is clean.")
            return
        elif status == 'fully_patched':
            st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
            st.success("✅ All vulnerabilities successfully patched.")
        elif status == 'partially_patched':
            st.markdown("<style>div.stAlert{max-width:fit-content !important;}</style>", unsafe_allow_html=True)
            st.warning("⚠️ Some vulnerabilities remain after patching.")
        
        # Summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            # Total detected = custom (initial) + bandit (initial) + semgrep (initial) + all iteration findings
            initial_custom = results.get('metrics', {}).get('custom_detector_initial', 0)
            initial_bandit = len(results.get('bandit_original', {}).get('issues', [])) if results.get('bandit_original', {}).get('success') else 0
            initial_semgrep = len(results.get('semgrep_original', {}).get('issues', [])) if results.get('semgrep_original', {}).get('success') else 0
            metrics_obj = results.get('metrics', {})
            total_detected = (
                metrics_obj.get('total_detected_all_occurrences')
                or results.get('total_vulns_found_all_occurrences')
                or len(results.get('all_found_vulns_occurrences', []))
                or metrics_obj.get('total_detected', 0)
            )
            st.metric("Total Vulnerabilities Found", total_detected)
        with col2:
            # Unique vulnerabilities (deduplicated across all phases)
            unique_detected = metrics_obj.get('total_detected', 0)
            st.metric("Unique Vulnerabilities", unique_detected)
        with col3:
            total_fixed = results.get('metrics', {}).get('total_fixed', 0)
            st.metric("Total Vulnerabilities Fixed", total_fixed)
        with col4:
            st.metric("Patch Iterations", results.get('total_iterations', 0))
        with col5:
            success_rate = results.get('metrics', {}).get('overall_success_rate', 0)
            st.metric("Success Rate", f"{success_rate:.1%}")
        
        # Additional breakdown metrics
        col5, col6 = st.columns(2)
        with col5:
            # Total in initial code = sum of custom + bandit + semgrep from initial run
            initial_custom = results.get('initial_custom_count', 0)
            initial_bandit = results.get('initial_bandit_count', 0)
            initial_semgrep = results.get('initial_semgrep_count', 0)
            initial_total = initial_custom + initial_bandit + initial_semgrep
            st.metric("Total Vulnerabilities Found in Initial Code", initial_total)
        with col6:
            # Total in iterations = sum of all tool findings in iterations
            iteration_custom = results.get('iteration_custom_count', 0)
            iteration_bandit = results.get('iteration_bandit_count', 0)
            iteration_semgrep = results.get('iteration_semgrep_count', 0)
            iterations_total = iteration_custom + iteration_bandit + iteration_semgrep
            st.metric("Total Vulnerabilities Found in Iterations", iterations_total)
        
        # Detected Vulnerabilities Custom Detector- Collect from initial and all iterations
        st.markdown("### 🔴 Custom Detector Vulnerability")
        st.info("ℹ️ This table shows the vulnerabilities identified in the initial source code.  For patching iteration verbosity, please refer to the report section.")

        # Collect initial vulnerabilities only
        initial_vulns = results.get('vulnerabilities_with_explanations', [])
        
        # Build vulnerability tracking for initial code only
        initial_vulns_tracking = {}
        
        # Add initial vulnerabilities
        for v in initial_vulns:
            cwe_id = v.get('cwe_id')
            key = (cwe_id, v.get('cwe_name'))
            if key not in initial_vulns_tracking:
                initial_vulns_tracking[key] = {
                    'cwe_id': cwe_id,
                    'cwe_name': v.get('cwe_name'),
                    'severity': v.get('severity'),
                    'description': v.get('description'),
                    'explanation': v.get('explanation'),
                    'patch_note': v.get('patch_note'),
                    'priority': v.get('remediation_priority'),
                    'lines': [],
                    'all_occurrences': []
                }
            initial_vulns_tracking[key]['lines'].append(v.get('line_number'))
            initial_vulns_tracking[key]['all_occurrences'].append({
                'line': v.get('line_number'),
                'snippet': v.get('code_snippet', ''),
                'explanation': v.get('explanation', '')
            })
        
        if initial_vulns_tracking:
            # Summary table - initial code vulnerabilities only
            vuln_data = []
            for key, g in initial_vulns_tracking.items():
                # Get unique sorted lines
                unique_lines = sorted(set(g['lines']), key=lambda x: int(x) if str(x).isdigit() else 0)
                lines_str = ', '.join(str(l) for l in unique_lines)
                
                vuln_data.append({
                    'CWE ID': f"CWE-{g['cwe_id']}",
                    'Name': g['cwe_name'],
                    'Severity': g['severity'],
                    'Occurrences': len(g['all_occurrences']),
                    'Lines': lines_str,
                    'Priority': g['priority']
                })
            
            st.dataframe(vuln_data, use_container_width=True)
    
            
            # Enhanced detailed vulnerability view with better organization
            with st.expander("📋 View Detailed Vulnerability Information - " + str(sum(len(g['all_occurrences']) for g in initial_vulns_tracking.values()))):
                for idx, (key, g) in enumerate(initial_vulns_tracking.items(), 1):
                    # Use columns for better layout
                    col_header, col_stats = st.columns([3, 1])
                    with col_header:
                        st.markdown(f"#### {idx}. CWE-{g['cwe_id']}: {g['cwe_name']}")
                    with col_stats:
                        st.metric("Total Occurrences", len(g['all_occurrences']))
                    
                    with st.container():
                        st.markdown("**Description:**")
                        st.info(g['description'])
                        
                        st.markdown("**Explanation:**")
                        st.info(g['explanation'])
                        
                        st.markdown("**Patch Recommendation:**")
                        st.success(g['patch_note'])
                    
                    # Show occurrences with code context
                    st.markdown("**Occurrences Details:**")
                    
                    for occ_idx, occ in enumerate(g['all_occurrences'], 1):
                        # Show filename/source if available, else fallback to a default label
                        source_file = v.get('filename', 'Source Code') if 'filename' in v else 'Source Code'
                        st.markdown(f"**{occ_idx}. {source_file} - Line {occ['line']}**")
                        if occ['snippet']:
                            st.code(occ['snippet'], language='python')
                    
                    st.markdown("---")
        
        else:
            st.success("✅ No vulnerabilities detected by Custom Detector!")
        
        # Show patched code if available
        st.markdown("### 🔧 Code Difference")
        
        # Get the cleaned code (preprocessed code that was analyzed)
        cleaned_code = results.get('cleaned_code', '')
        # Get final patched code (with 0 vulnerabilities)
        final_patched_code = results.get('final_patched_code', '')
        
        # Show status message based on remaining vulnerabilities BEFORE showing code
        if cleaned_code and final_patched_code:
            remaining_vulns = results.get('metrics', {}).get('total_remaining', 0)
            if remaining_vulns == 0:
                st.success("✅ Code has been successfully patched with 0 vulnerabilities remaining!")
            else:
                st.warning(f"⚠️ The final patched code is partially fixed. {remaining_vulns} vulnerability(ies) couldn't be fixed and remain in the code.")
        
        # Show code comparison if both exist
        if cleaned_code and final_patched_code:
            col_orig, col_patch = st.columns(2)
            
            with col_orig:
                st.markdown("#### Original Code")                
                st.code(_add_line_numbers(cleaned_code), language='python')
            
            with col_patch:
                st.markdown("#### Final Patched Code")
                st.code(_add_line_numbers(final_patched_code), language='python')
        elif cleaned_code:
            st.info("✅ No vulnerabilities were found - code is already secure!")
            st.markdown("#### Original Code")
            st.code(_add_line_numbers(cleaned_code), language='python')
        else:
            st.info("No code available to display.")

        # Vulnerability fix summary (fixed vs remaining)
        st.markdown("### 🛡️ Vulnerability Fix Summary")

        def _normalize_cwe(cwe_raw):
            cwe_id, _ = parse_cwe_info(cwe_raw)
            return cwe_id or "N/A"

        def _normalize_line(entry):
            line_val = entry.get('line') or entry.get('line_number') or entry.get('start', {}).get('line')
            try:
                return int(line_val) if line_val not in (None, "") else "Unknown"
            except Exception:
                return line_val or "Unknown"

        def _friendly_source(src: str) -> str:
            src = (src or "custom").lower()
            if src in {"bandit", "semgrep", "custom"}:
                return src
            return "custom"

        def _convert_bandit_remaining(bandit_result: dict) -> list:
            items = []
            if bandit_result and bandit_result.get('success'):
                for issue in bandit_result.get('issues', []):
                    items.append({
                        'cwe_id': _normalize_cwe(issue.get('cwe_id', 'N/A')),
                        'line': issue.get('line_number'),
                        'detection_method': 'bandit',
                        'description': issue.get('issue_text', issue.get('test_name', 'Bandit issue'))
                    })
            return items

        def _convert_semgrep_remaining(semgrep_result: dict) -> list:
            items = []
            if semgrep_result and semgrep_result.get('success'):
                for issue in semgrep_result.get('issues', []):
                    line_number = None
                    if 'start' in issue:
                        line_number = issue['start'].get('line')
                    elif 'end' in issue:
                        line_number = issue['end'].get('line')
                    elif 'line_number' in issue:
                        line_number = issue.get('line_number')
                    items.append({
                        'cwe_id': _normalize_cwe(issue.get('cwe_id', 'N/A')),
                        'line': line_number,
                        'detection_method': 'semgrep',
                        'description': issue.get('message', issue.get('description', 'Semgrep issue'))
                    })
            return items

        # All occurrences across initial and iterations (prefer total list when available)
        all_occurrences = (
            results.get('all_found_vulns_total')
            or results.get('all_found_vulns_occurrences')
            or results.get('all_found_vulns_initial')
            or []
        )

        # Count per CWE and tool; keep only CWEs seen by all three tools
        cwe_tool_counts = {}
        for occ in all_occurrences:
            cwe_id = _normalize_cwe(occ.get('cwe_id', 'N/A'))
            tool = _friendly_source(occ.get('detection_method') or occ.get('source'))
            if cwe_id == 'N/A':
                continue
            bucket = cwe_tool_counts.setdefault(cwe_id, {'custom': 0, 'bandit': 0, 'semgrep': 0})
            if tool in bucket:
                bucket[tool] += 1

        # Remaining vulnerabilities (final state)
        remaining_raw = []
        patch_iterations = results.get('patch_iterations', []) or []
        if patch_iterations:
            remaining_raw.extend(patch_iterations[-1].get('unpatched_vulns', []))
        remaining_raw.extend(_convert_bandit_remaining(results.get('bandit_final', {})))
        remaining_raw.extend(_convert_semgrep_remaining(results.get('secondary_final', results.get('semgrep_final', {}))))

        remaining_map = {}
        for rem in remaining_raw:
            cwe_id = _normalize_cwe(rem.get('cwe_id', 'N/A'))
            line_num = _normalize_line(rem)
            key = (cwe_id, line_num)
            entry = remaining_map.setdefault(key, {
                'cwe_id': cwe_id,
                'line': line_num,
                'methods': set(),
                'description': rem.get('description', '')
            })
            entry['methods'].add(_friendly_source(rem.get('detection_method') or rem.get('source')))

        remaining_counts = {}
        for key, data in remaining_map.items():
            remaining_counts.setdefault(data['cwe_id'], {'count': 0, 'methods': set(), 'description': data.get('description', '')})
            remaining_counts[data['cwe_id']]['count'] += 1
            remaining_counts[data['cwe_id']]['methods'].update(data['methods'])

        fixed_rows = []
        for cwe_id, tool_counts in cwe_tool_counts.items():
            total_occ = tool_counts['custom'] + tool_counts['bandit'] + tool_counts['semgrep']
            remaining_for_cwe = remaining_counts.get(cwe_id, {'count': 0})['count']
            fixed_count = max(0, total_occ - remaining_for_cwe)
            if fixed_count <= 0:
                continue
            
            # Build identified text with tool counts
            tools_found = []
            if tool_counts['custom'] > 0:
                tools_found.append(f"Custom ({tool_counts['custom']})")
            if tool_counts['bandit'] > 0:
                tools_found.append(f"Bandit ({tool_counts['bandit']})")
            if tool_counts['semgrep'] > 0:
                tools_found.append(f"Semgrep ({tool_counts['semgrep']})")
            
            # Indicate if all 3 tools found it
            all_three = all(tool_counts[t] > 0 for t in ['custom', 'bandit', 'semgrep'])
            identified_text = ", ".join(tools_found)
            if all_three:
                identified_text = "✓ All 3 tools: " + identified_text
            
            fixed_rows.append({
                'CWE': cwe_id,
                'Occurrences': total_occ,
                'Identified By': identified_text
            })

        unfixed_rows = []
        for cwe_id, rem in remaining_counts.items():
            tool_counts = cwe_tool_counts.get(cwe_id, {'custom': 0, 'bandit': 0, 'semgrep': 0})
            
            # Build identified text with tool counts
            tools_found = []
            if tool_counts['custom'] > 0:
                tools_found.append(f"Custom ({tool_counts['custom']})")
            if tool_counts['bandit'] > 0:
                tools_found.append(f"Bandit ({tool_counts['bandit']})")
            if tool_counts['semgrep'] > 0:
                tools_found.append(f"Semgrep ({tool_counts['semgrep']})")
            
            # Indicate if all 3 tools found it
            all_three = all(tool_counts[t] > 0 for t in ['custom', 'bandit', 'semgrep'])
            identified_text = ", ".join(tools_found) if tools_found else "Unknown"
            if all_three:
                identified_text = "✓ All 3 tools: " + identified_text
            
            unfixed_rows.append({
                'CWE': cwe_id,
                'Remaining Occurrences': rem['count'],
                'Identified By': identified_text
            })

        total_remaining_overall = len(remaining_map)

        col_fixed, col_unfixed = st.columns(2)
        with col_fixed:
            with st.expander(f"✅ Fixed Vulnerabilities ({len(fixed_rows)})", expanded=False):
                if fixed_rows:
                    st.dataframe(pd.DataFrame(fixed_rows), use_container_width=True, hide_index=True)
                else:
                    st.success("No fixed vulnerabilities to display.")
        with col_unfixed:
            with st.expander(f"⚠️ Remaining Vulnerabilities ({total_remaining_overall})", expanded=False):
                if remaining_map:
                    # Show each remaining vulnerability with CWE, line, and code
                    cleaned_code = results.get('cleaned_code', '')
                    final_code = results.get('final_patched_code', cleaned_code)
                    code_lines = final_code.split('\n') if final_code else []
                    
                    for idx, (key, data) in enumerate(remaining_map.items(), 1):
                        cwe_id = data['cwe_id']
                        line_num = data['line']
                        cwe_name = get_cwe_name(cwe_id.replace('CWE-', '')) if cwe_id != 'N/A' else 'Unknown'
                        
                        st.markdown(f"**{idx}. {cwe_id}: {cwe_name}** (Line {line_num})")
                        
                        # Show code context (3 lines: before, target, after)
                        try:
                            line_idx = int(line_num) - 1
                            start = max(0, line_idx - 1)
                            end = min(len(code_lines), line_idx + 2)
                            
                            snippet_lines = []
                            for ln in range(start, end):
                                prefix = "→" if (ln + 1) == int(line_num) else " "
                                safe_line = code_lines[ln].rstrip() if ln < len(code_lines) else ""
                                snippet_lines.append(f"{prefix} {ln + 1:>4}: {safe_line}")
                            
                            if snippet_lines:
                                st.code("\n".join(snippet_lines), language='python')
                        except (ValueError, TypeError, IndexError):
                            st.warning("⚠️ Code context unavailable for this line")
                        
                        st.markdown("---")
                else:
                    st.success("All identified vulnerabilities were fixed.")
        
        # Static Analysis Results - Initial Code Only
        st.markdown("### 🔬 Static Analysis Results")
        
        # Calculate total vulnerabilities from Bandit and Semgrep
        bandit_original = results.get('bandit_original', {})
        secondary_original = results.get('semgrep_original', results.get('secondary_original', {}))
        
        bandit_original_count = len(bandit_original.get('issues', [])) if bandit_original.get('success') else 0
        semgrep_original_count = len(secondary_original.get('issues', [])) if secondary_original.get('success') else 0
        
        # Count vulnerabilities found across all iterations
        patch_iterations = results.get('patch_iterations', [])
        bandit_iteration_count = 0
        semgrep_iteration_count = 0
        
        for iteration in patch_iterations:
            bandit_analysis = iteration.get('bandit_analysis', {})
            semgrep_analysis = iteration.get('semgrep_analysis', {})
            
            if bandit_analysis.get('success'):
                bandit_iteration_count += len(bandit_analysis.get('issues', []))
            
            if semgrep_analysis.get('success'):
                semgrep_iteration_count += len(semgrep_analysis.get('issues', []))
        
        total_static_vulns = bandit_original_count + bandit_iteration_count + semgrep_original_count + semgrep_iteration_count
        st.metric("Total Vulnerabilities Found", total_static_vulns)   

        col_bandit, col_secondary = st.columns(2)
        
        with col_bandit:
            st.markdown("#### Bandit Analysis")
            
            col_bandit_1, col_bandit_2 = st.columns(2)
            with col_bandit_1:
                st.metric("Total Issues Found in Initial Code", bandit_original_count)
            with col_bandit_2:
                st.metric("Total Issues Found in Iterations", bandit_iteration_count)
            
            if bandit_original_count > 0:
                with st.expander(f"🔍 View Bandit Issues - {bandit_original_count}"):
                    # Bandit runs on cleaned_code in the backend; use the same to align line numbers
                    bandit_source_code = results.get('cleaned_code', results.get('original_code', ''))
                    code_lines = bandit_source_code.split('\n') if bandit_source_code else []
                    
                    for idx, issue in enumerate(bandit_original.get('issues', []), 1):
                        test_id = issue.get('test_id', 'N/A')
                        issue_text = issue.get('issue_text', issue.get('test_name', 'Bandit Issue'))
                        line_number = issue.get('line_number', 0)
                        cwe_raw = issue.get('cwe_id', 'N/A')
                        cwe_id, cwe_name = parse_cwe_info(cwe_raw)

                        # Display issue info with CWE
                        cwe_display = f" [{cwe_id}]" if cwe_id != 'N/A' else ""
                        st.markdown(f"**{idx}. {test_id}** - {issue_text} (Line {line_number}){cwe_display}")

                        # Show a 3-line window around the vulnerable line with an arrow
                        if line_number and 1 <= line_number <= len(code_lines):
                            start = max(1, line_number - 1)  # ensure at least one line before when possible
                            end = min(len(code_lines), line_number + 1)  # ensure at least one line after when possible
                            snippet_lines = []
                            for ln in range(start, end + 1):
                                prefix = "→" if ln == line_number else " "
                                safe_line = code_lines[ln - 1].rstrip()
                                snippet_lines.append(f"{prefix} {ln:>4}: {safe_line}")
                            # If we ended up with only 2 lines (file too short), try to extend to 3 when possible
                            if len(snippet_lines) < 3 and end < len(code_lines):
                                ln = end + 1
                                safe_line = code_lines[ln - 1].rstrip()
                                snippet_lines.append(f"  {ln:>4}: {safe_line}")
                            st.markdown("```python\n" + "\n".join(snippet_lines) + "\n```")
                        else:
                            st.warning("⚠️ Code context unavailable for this line")

                        st.markdown("---")
            else:
                st.success("✅ No issues found by Bandit in initial code!")
        
        with col_secondary:
            st.markdown("#### Semgrep Analysis")
            
            col_semgrep_1, col_semgrep_2 = st.columns(2)
            with col_semgrep_1:
                st.metric("Total Issues Found in Initial Code", semgrep_original_count)
            with col_semgrep_2:
                st.metric("Total Issues Found in Iterations", semgrep_iteration_count)
            
            if semgrep_original_count > 0:
                with st.expander(f"🔍 View Semgrep Issues - {semgrep_original_count}"):
                    # Semgrep runs on cleaned_code; use the same to align line numbers
                    semgrep_source_code = results.get('cleaned_code', results.get('original_code', ''))
                    code_lines = semgrep_source_code.split('\n') if semgrep_source_code else []
                    
                    for idx, issue in enumerate(secondary_original.get('issues', []), 1):
                        check_id = issue.get('check_id', issue.get('message_id', 'N/A'))
                        description = issue.get('description', issue.get('message', 'Semgrep Issue'))
                        cwe_raw = issue.get('cwe_id', 'N/A')
                        cwe_id, cwe_name = parse_cwe_info(cwe_raw)
                        
                        # Get line number from start or end position
                        line_number = 'Unknown'
                        if 'start' in issue:
                            line_number = issue['start'].get('line', 'Unknown')
                        elif 'end' in issue:
                            line_number = issue['end'].get('line', 'Unknown')
                        elif 'line_number' in issue:
                            line_number = issue.get('line_number', 'Unknown')

                        # Display issue info with CWE
                        cwe_display = f" [{cwe_id}]" if cwe_id != 'N/A' else ""
                        st.markdown(f"{idx} : {check_id}")
                        st.markdown(f"**Description:** {description}")
                        st.markdown(f"**Line:** {line_number} {cwe_display}")

                        # Show a 3-line window around the vulnerable line with an arrow
                        if isinstance(line_number, int) and 1 <= line_number <= len(code_lines):
                            start = max(1, line_number - 1)
                            end = min(len(code_lines), line_number + 1)
                            snippet_lines = []
                            for ln in range(start, end + 1):
                                prefix = "→" if ln == line_number else " "
                                safe_line = code_lines[ln - 1].rstrip()
                                snippet_lines.append(f"{prefix} {ln:>4}: {safe_line}")
                            if len(snippet_lines) < 3 and end < len(code_lines):
                                ln = end + 1
                                safe_line = code_lines[ln - 1].rstrip()
                                snippet_lines.append(f"  {ln:>4}: {safe_line}")
                            st.markdown("```python\n" + "\n".join(snippet_lines) + "\n```")
                        else:
                            st.warning("⚠️ Code context unavailable for this line")

                        st.markdown("---")
            else:
                st.success("✅ No issues found by Semgrep in initial code!")

        # Combined vulnerability table from original and all patched iterations
        combined_issues = []

        bandit_original = results.get('bandit_original', {})
        secondary_original = results.get('semgrep_original', results.get('secondary_original', {}))
        patch_iterations = results.get('patch_iterations', [])
        
        # Add vulnerabilities from original code - Bandit
        if bandit_original.get('success'):
            for issue in bandit_original.get('issues', []):
                line_num = issue.get('line_number', 'Unknown')
                severity = issue.get('issue_severity') or issue.get('severity', 'UNKNOWN')
                confidence = issue.get('issue_confidence') or issue.get('confidence', 'UNKNOWN')
                cwe_raw = issue.get('cwe_id', 'N/A')
                cwe_id, cwe_name = parse_cwe_info(cwe_raw)
                combined_issues.append({
                    'CWE ID': cwe_id,
                    'CWE Name': cwe_name,
                    'Severity': severity,
                    'Confidence': confidence,
                    'Line Number': line_num
                })

        # Bandit table (if any)
        if combined_issues:
            st.markdown("### 🔴 Detected Vulnerabilities - Bandit")
            st.info("ℹ️ This table shows the vulnerabilities identified by Bandit tool in the initial source code. For patching iteration verbosity, please refer to the report section.")
            df = pd.DataFrame(combined_issues)
            df.insert(0, 'SL.No', range(1, len(df) + 1))
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("ℹ️ No vulnerabilities identified by Bandit in the initial source code.")

        # Semgrep table (always show when available)
        if semgrep_original_count > 0:
            st.info("ℹ️ This table shows the vulnerabilities identified by Semgrep tool in the initial source code. For patching iteration verbosity, please refer to the report section.")
            semgrep_issues_data = []
            for idx, issue in enumerate(secondary_original.get('issues', []), 1):
                line_num = 'Unknown'
                if 'start' in issue:
                    line_num = issue['start'].get('line', 'Unknown')
                elif 'end' in issue:
                    line_num = issue['end'].get('line', 'Unknown')
                elif 'line_number' in issue:
                    line_num = issue.get('line_number', 'Unknown')

                cwe_raw = issue.get('cwe_id', 'N/A')
                cwe_id, cwe_name = parse_cwe_info(cwe_raw)

                row = {
                    'SL.No': idx,
                    'CWE ID': cwe_id,
                    'CWE Name': cwe_name,
                    'Line Number': line_num
                }

                if 'severity' in issue:
                    row['Severity'] = issue.get('severity', 'UNKNOWN')

                if 'confidence' in issue:
                    row['Confidence'] = issue.get('confidence', 'UNKNOWN')

                semgrep_issues_data.append(row)

            if semgrep_issues_data:
                st.dataframe(pd.DataFrame(semgrep_issues_data), use_container_width=True, hide_index=True)

        # Get metrics early for use in cross-validation section
        metrics = results.get('metrics', {})
        
        # Tool Comparison and Cross-Validation
        st.markdown("### 🔄 Analysis Summary")
        st.info("_Total vulnerabilities from all detection tools across all iterations_")
        
        col_compare1, col_compare2 = st.columns(2)
        
        with col_compare1:
            with st.expander("📊 Total Vulnerabilities Detected"):                
                total_detected = (
                    metrics.get('total_detected_all_occurrences')
                    or results.get('total_vulns_found_all_occurrences')
                    or len(results.get('all_found_vulns_occurrences', []))
                    or metrics.get('total_detected', 0)
                )
                custom_total = results.get('total_custom_count', 0)
                bandit_total = results.get('total_bandit_count', 0)
                semgrep_total = results.get('total_semgrep_count', 0)
                total_remaining = metrics.get('total_remaining', 0)

                st.write(f"- Total detected: **{total_detected}** vulnerabilities")
                st.write(f"- Custom Detector: **{custom_total}**")
                st.write(f"- Bandit: **{bandit_total}**")
                st.write(f"- Semgrep: **{semgrep_total}**")
                st.write(f"\n**Total Remaining: {total_remaining}**")
        
        
        # Metrics
        st.markdown("### 📊 Effectiveness Metrics")
        
        if metrics:
            patching_eff = metrics.get('patching_effectiveness', {})
            tool_comp = metrics.get('tool_comparison', {})

            st.markdown("#### Patching Effectiveness (Summary)")
            eff_rows = [{
                'Sl.No': 1,
                'Fix Rate': f"{patching_eff.get('fix_rate', 0):.1%}",
                'Effectiveness Score': f"{patching_eff.get('effectiveness_score', 0):.1%}",
                'Vulnerabilities Fixed': metrics.get('total_fixed', 0),
                'Vulnerabilities Remaining': metrics.get('total_remaining_all_occurrences', 0)
            }]
            st.table(pd.DataFrame(eff_rows).set_index('Sl.No'))

            st.markdown("#### Tool Comparison")
            comp_rows = [{
                'Sl.No': 1,
                'Custom Detector Total': results.get('total_custom_count', 0),
                'Bandit Total': results.get('total_bandit_count', 0),
                'Semgrep Total': results.get('total_semgrep_count', 0),
                'Overlapping Detections': tool_comp.get('overlapping_detections', 0),
                'Overlap Rate': f"{tool_comp.get('overlap_rate', 0):.1%}"
            }]
            st.table(pd.DataFrame(comp_rows).set_index('Sl.No'))
        
        # Export Reports
        st.markdown("### 📄 Generated Reports")
        final_reports = results.get('final_reports', {})
        
        if final_reports:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if final_reports.get('metrics') and os.path.exists(final_reports['metrics']):
                    with open(final_reports['metrics'], 'rb') as f:
                        st.download_button(
                            label="📊 Download Metrics Report (HTML)",
                            data=f.read(),
                            file_name=os.path.basename(final_reports['metrics']),
                            mime='text/html',
                            key='download_metrics'
                        )
            
            with col2:
                if final_reports.get('html_summary') and os.path.exists(final_reports['html_summary']):
                    with open(final_reports['html_summary'], 'rb') as f:
                        st.download_button(
                            label="📄 Download Analysis Summary (HTML)",
                            data=f.read(),
                            file_name=os.path.basename(final_reports['html_summary']),
                            mime='text/html',
                            key='download_html'
                        )
            
            with col3:
                # Generate iteration-focused report
                iteration_report_html = self._generate_iteration_report(results)
                st.download_button(
                    label="🔄 Download Iteration Report (HTML)",
                    data=iteration_report_html,
                    file_name=f"iteration_report_{results.get('workflow_id', 'unknown')}.html",
                    mime='text/html',
                    key='download_iteration_report'
                )
        
    def _generate_iteration_report(self, results: dict) -> str:
        """Generate comprehensive HTML report focused on iteration analysis."""
        patch_iterations = results.get('patch_iterations', [])
        metrics = results.get('metrics', {})
        
        # Get the total vulnerabilities found in iterations from metrics
        total_all_tools = metrics.get('all_iterations_deduped_count', 0)
        
        # Count vulnerabilities by tool across all iterations
        custom_total = 0
        bandit_total = 0
        semgrep_total = 0
        
        # Store vulnerabilities organized by iteration and tool
        iterations_data = {}
        
        # Collect all vulnerabilities from iterations only
        for idx, iteration in enumerate(patch_iterations, 1):
            iter_code = iteration.get('patched_code', '')
            iterations_data[idx] = {
                'code': iter_code,
                'custom_detector': [],
                'bandit': [],
                'semgrep': []
            }
            
            # Custom detector vulnerabilities in this iteration
            # Check for vulnerabilities key first, then custom_detector_vulns
            custom_vulns = []
            if 'vulnerabilities' in iteration:
                custom_vulns = iteration['vulnerabilities']
            elif 'custom_detector_vulns' in iteration:
                # Convert from the stored format to list format
                for (cwe_id, cwe_name), vuln_info in iteration['custom_detector_vulns'].items():
                    for line in vuln_info.get('lines', []):
                        custom_vulns.append({
                            'cwe_id': cwe_id,
                            'cwe_name': cwe_name,
                            'line_number': line,
                            'severity': 'HIGH',
                            'remediation_priority': 'HIGH'
                        })
            
            for v in custom_vulns:
                custom_total += 1
                iterations_data[idx]['custom_detector'].append({
                    'id': f"CWE-{v.get('cwe_id')}",
                    'name': v.get('cwe_name', 'Unknown'),
                    'severity': v.get('severity', 'UNKNOWN'),
                    'line': v.get('line_number', 'Unknown'),
                    'priority': v.get('remediation_priority', 'MEDIUM'),
                    'snippet': v.get('code_snippet', '')
                })
            
            # Bandit vulnerabilities in this iteration
            bandit_analysis = iteration.get('bandit_analysis', {})
            print(f"[DEBUG] Iteration {idx} bandit_analysis: {bandit_analysis}")
            if bandit_analysis.get('success'):
                for issue in bandit_analysis.get('issues', []):
                    bandit_total += 1
                    # Bandit uses 'severity' not 'issue_severity'
                    severity = issue.get('severity', issue.get('issue_severity', 'MEDIUM'))
                    cwe_raw = issue.get('cwe_id', 'N/A')
                    cwe_id, cwe_name = parse_cwe_info(cwe_raw)
                    iterations_data[idx]['bandit'].append({
                        'id': issue.get('test_id', 'N/A'),
                        'name': issue.get('test_name', issue.get('description', 'Bandit Issue')),
                        'cwe_id': cwe_id,
                        'cwe_name': cwe_name,
                        'severity': severity,
                        'line': issue.get('line_number', 'Unknown'),
                        'priority': 'HIGH' if severity == 'HIGH' else 'MEDIUM'
                    })
            
            # Semgrep vulnerabilities in this iteration
            semgrep_analysis = iteration.get('semgrep_analysis', {})
            print(f"[DEBUG] Iteration {idx} semgrep_analysis: {semgrep_analysis}")
            if semgrep_analysis.get('success'):
                for issue in semgrep_analysis.get('issues', []):
                    semgrep_total += 1
                    # Semgrep uses 'check_id' and 'start'/'end' for line numbers
                    line_num = 'Unknown'
                    if 'start' in issue:
                        line_num = issue['start'].get('line', 'Unknown')
                    elif 'line_number' in issue:
                        line_num = issue.get('line_number', 'Unknown')
                    
                    severity = issue.get('severity', 'UNKNOWN')
                    cwe_raw = issue.get('cwe_id', 'N/A')
                    cwe_id, cwe_name = parse_cwe_info(cwe_raw)
                    iterations_data[idx]['semgrep'].append({
                        'id': issue.get('check_id', issue.get('message_id', issue.get('symbol', 'N/A'))),
                        'name': issue.get('message', 'Semgrep Issue'),
                        'cwe_id': cwe_id,
                        'cwe_name': cwe_name,
                        'severity': severity,
                        'line': line_num,
                        'priority': 'HIGH' if severity in ['HIGH', 'CRITICAL'] else 'MEDIUM'
                    })
        
        # Calculate total as sum of all tool counts
        total_all_tools = custom_total + bandit_total + semgrep_total
        
        # Debug output to understand what's being collected
        print(f"\n[DEBUG Iteration Report] Custom total: {custom_total}, Bandit total: {bandit_total}, Semgrep total: {semgrep_total}")
        print(f"[DEBUG Iteration Report] Total (sum): {total_all_tools}")
        print(f"[DEBUG Iteration Report] Iterations data: {iterations_data}")
        for iter_num, iter_data in iterations_data.items():
            print(f"[DEBUG] Iteration {iter_num}: {len(iter_data['custom_detector'])} custom, {len(iter_data['bandit'])} bandit, {len(iter_data['semgrep'])} semgrep")
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Iteration Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .summary-section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .metric-box {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-box.custom {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}
        .metric-box.bandit {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        .metric-box.semgrep {{
            background: linear-gradient(135deg, #30cfd0 0%, #330867 100%);
        }}
        .metric-value {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            margin-top: 20px;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .severity-HIGH, .severity-CRITICAL {{
            background-color: #dc3545;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-MEDIUM {{
            background-color: #ffc107;
            color: #333;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-LOW {{
            background-color: #28a745;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .code-section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            line-height: 1.6;
            margin-top: 15px;
        }}
        .code-line {{
            white-space: pre;
        }}
        .code-line-highlight {{
            background-color: #e74c3c;
            color: white;
            display: block;
            margin: 0 -20px;
            padding: 0 20px;
        }}
        .arrow {{
            color: #f39c12;
            font-weight: bold;
            margin-right: 5px;
        }}
        .iteration-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            margin: 30px 0 20px 0;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .tool-header {{
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            margin-top: 20px;
            margin-bottom: 10px;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .no-vulns {{
            color: #28a745;
            font-style: italic;
            padding: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔄 Iteration Analysis Report</h1>
        <p>Vulnerabilities identified in patching iterations</p>
    </div>
    
    <div class="summary-section">
        <h2>📊 Total Vulnerabilities Found in Iterations</h2>
        <div class="metric-container">
            <div class="metric-box">
                <div class="metric-label">Total Vulnerabilities</div>
                <div class="metric-value">{total_all_tools}</div>
                <div class="metric-label">All Tools Combined</div>
            </div>
            <div class="metric-box custom">
                <div class="metric-label">Custom Detector</div>
                <div class="metric-value">{custom_total}</div>
                <div class="metric-label">Issues Found</div>
            </div>
            <div class="metric-box bandit">
                <div class="metric-label">Bandit</div>
                <div class="metric-value">{bandit_total}</div>
                <div class="metric-label">Issues Found</div>
            </div>
            <div class="metric-box semgrep">
                <div class="metric-label">Semgrep</div>
                <div class="metric-value">{semgrep_total}</div>
                <div class="metric-label">Issues Found</div>
            </div>
        </div>
        
        <h2>🔍 All CWEs Identified by Each Tool</h2>
        <table>
            <thead>
                <tr>
                    <th>CWE ID</th>
                    <th>CWE Name</th>
                    <th>Identified By</th>
                    <th>Occurrences</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Build CWE summary table (all CWEs found across all iterations by all tools)
        cwe_summary = {}
        for iter_num, iter_data in iterations_data.items():
            for vuln in iter_data['custom_detector']:
                cwe_id = vuln['id']
                cwe_name = vuln['name']
                key = (cwe_id, cwe_name)
                if key not in cwe_summary:
                    cwe_summary[key] = {'custom': 0, 'bandit': 0, 'semgrep': 0}
                cwe_summary[key]['custom'] += 1
            
            for vuln in iter_data['bandit']:
                cwe_id = vuln.get('cwe_id', 'N/A')
                cwe_name = vuln.get('cwe_name', 'Unknown')
                key = (cwe_id, cwe_name)
                if key not in cwe_summary:
                    cwe_summary[key] = {'custom': 0, 'bandit': 0, 'semgrep': 0}
                cwe_summary[key]['bandit'] += 1
            
            for vuln in iter_data['semgrep']:
                cwe_id = vuln.get('cwe_id', 'N/A')
                cwe_name = vuln.get('cwe_name', 'Unknown')
                key = (cwe_id, cwe_name)
                if key not in cwe_summary:
                    cwe_summary[key] = {'custom': 0, 'bandit': 0, 'semgrep': 0}
                cwe_summary[key]['semgrep'] += 1
        
        # Generate CWE summary rows
        for (cwe_id, cwe_name), counts in sorted(cwe_summary.items()):
            tools_found = []
            if counts['custom'] > 0:
                tools_found.append(f"Custom ({counts['custom']})")
            if counts['bandit'] > 0:
                tools_found.append(f"Bandit ({counts['bandit']})")
            if counts['semgrep'] > 0:
                tools_found.append(f"Semgrep ({counts['semgrep']})")
            
            identified_by = ", ".join(tools_found)
            total_occ = counts['custom'] + counts['bandit'] + counts['semgrep']
            
            html += f"""
                <tr>
                    <td><strong>{cwe_id}</strong></td>
                    <td>{cwe_name}</td>
                    <td>{identified_by}</td>
                    <td>{total_occ}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
"""
        
        # Add each iteration with its vulnerabilities
        for iter_num, iter_data in iterations_data.items():
            iter_code = iter_data['code']
            custom_vulns = iter_data['custom_detector']
            bandit_vulns = iter_data['bandit']
            semgrep_vulns = iter_data['semgrep']

            # Skip rendering this iteration if no vulnerabilities were found
            if not (custom_vulns or bandit_vulns or semgrep_vulns):
                continue

            # Collect all line numbers with vulnerabilities
            vuln_lines = set()
            for v in custom_vulns + bandit_vulns + semgrep_vulns:
                try:
                    vuln_lines.add(int(v['line']))
                except (ValueError, TypeError):
                    pass

            html += f"""
    <div class="code-section">
        <div class="iteration-header">🔄 Iteration {iter_num} - Patched Code</div>
        
        <div class="tool-header">Custom Detector - {len(custom_vulns)} Issue(s)</div>
"""
            if custom_vulns:
                html += """
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>Line</th>
                    <th>Priority</th>
                </tr>
            </thead>
            <tbody>
"""
                for vuln in custom_vulns:
                    html += f"""
                <tr>
                    <td><strong>{vuln['id']}</strong></td>
                    <td>{vuln['name']}</td>
                    <td><span class="severity-{vuln['severity']}">{vuln['severity']}</span></td>
                    <td>{vuln['line']}</td>
                    <td>{vuln['priority']}</td>
                </tr>
"""
                html += """
            </tbody>
        </table>
"""
            else:
                html += """<p class="no-vulns">✅ No vulnerabilities found</p>
"""
            
            html += f"""
        <div class="tool-header">Bandit - {len(bandit_vulns)} Issue(s)</div>
"""
            if bandit_vulns:
                html += """
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>CWE ID</th>
                    <th>Severity</th>
                    <th>Line</th>
                    <th>Priority</th>
                </tr>
            </thead>
            <tbody>
"""
                for vuln in bandit_vulns:
                    html += f"""
                <tr>
                    <td><strong>{vuln['id']}</strong></td>
                    <td>{vuln['name']}</td>
                    <td><strong>{vuln.get('cwe_id', 'N/A')}</strong></td>
                    <td><span class="severity-{vuln['severity']}">{vuln['severity']}</span></td>
                    <td>{vuln['line']}</td>
                    <td>{vuln['priority']}</td>
                </tr>
"""
                html += """
            </tbody>
        </table>
"""
            else:
                html += """<p class="no-vulns">✅ No vulnerabilities found</p>
"""
            
            html += f"""
        <div class="tool-header">Semgrep - {len(semgrep_vulns)} Issue(s)</div>
"""
            if semgrep_vulns:
                html += """
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>CWE ID</th>
                    <th>Severity</th>
                    <th>Line</th>
                    <th>Priority</th>
                </tr>
            </thead>
            <tbody>
"""
                for vuln in semgrep_vulns:
                    html += f"""
                <tr>
                    <td><strong>{vuln['id']}</strong></td>
                    <td>{vuln['name']}</td>
                    <td><strong>{vuln.get('cwe_id', 'N/A')}</strong></td>
                    <td><span class="severity-{vuln['severity']}">{vuln['severity']}</span></td>
                    <td>{vuln['line']}</td>
                    <td>{vuln['priority']}</td>
                </tr>
"""
                html += """
            </tbody>
        </table>
"""
            else:
                html += """<p class="no-vulns">✅ No vulnerabilities found</p>
"""
            
            # Add code display with highlighted lines
            html += """
        <div style="margin-top: 20px;">
            <h4>Code with Highlighted Vulnerabilities:</h4>
            <div class="code-block">
"""
            # Split code into lines, handling various line ending scenarios
            code_lines_list = iter_code.split('\n')
            # Remove trailing empty line if present (caused by trailing newline)
            if code_lines_list and code_lines_list[-1] == '':
                code_lines_list = code_lines_list[:-1]
            
            for line_num, line in enumerate(code_lines_list, 1):
                if line_num in vuln_lines:
                    escaped_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    html += f'<div class="code-line code-line-highlight"><span class="arrow">→</span>{line_num:>4}: {escaped_line}</div>\n'
                else:
                    escaped_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    html += f'<div class="code-line">  {line_num:>4}: {escaped_line}</div>\n'
            html += """
            </div>
        </div>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html
    
    def run(self):
        self.render_api_input()
        if st.session_state.api_loaded:
            self.render_main_ui()


if __name__ == "__main__":
    App().run()