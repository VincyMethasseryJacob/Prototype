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
                    try:
                        # Validate API key
                        OpenAIClientWrapper(api_key.strip())
                        st.session_state.api_key = api_key.strip()
                        st.session_state.api_loaded = True
                        st.session_state.securityeval_map = self.loader.load_prompts(TESTCASES_DIR)
                        st.session_state.api_init_error = ""
                        st.success("API key validated! Loading application…")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to initialize OpenAI client: {e}")
                        st.session_state.api_init_error = str(e)

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
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            total_detected = results.get('metrics', {}).get('total_detected', results.get('vulnerability_count', 0))
            st.metric("Total Vulnerabilities Found", total_detected)
        with col2:
            total_fixed = results.get('metrics', {}).get('total_fixed', 0)
            st.metric("Total Vulnerabilities Fixed", total_fixed)
        with col3:
            st.metric("Patch Iterations", results.get('total_iterations', 0))
        with col4:
            success_rate = results.get('metrics', {}).get('overall_success_rate', 0)
            st.metric("Success Rate", f"{success_rate:.1%}")
        
        # Detected Vulnerabilities Custom Detector- Collect from initial and all iterations
        st.markdown("### 🔴 Custom Detector Vulnerabilities")
        
        # Collect initial vulnerabilities
        initial_vulns = results.get('vulnerabilities_with_explanations', [])
        patch_iterations = results.get('patch_iterations', [])
        
        # Build comprehensive vulnerability tracking across all iterations
        all_vulns_tracking = {}
        
        # Add initial vulnerabilities
        for v in initial_vulns:
            cwe_id = v.get('cwe_id')
            key = (cwe_id, v.get('cwe_name'))
            if key not in all_vulns_tracking:
                all_vulns_tracking[key] = {
                    'cwe_id': cwe_id,
                    'cwe_name': v.get('cwe_name'),
                    'severity': v.get('severity'),
                    'description': v.get('description'),
                    'explanation': v.get('explanation'),
                    'patch_note': v.get('patch_note'),
                    'priority': v.get('remediation_priority'),
                    'initial_count': 0,
                    'iteration_counts': {},  # {iteration_num: count}
                    'all_lines': [],
                    'all_occurrences': []  # [{source, line, snippet, explanation}]
                }
            all_vulns_tracking[key]['initial_count'] += 1
            all_vulns_tracking[key]['all_lines'].append(v.get('line_number'))
            all_vulns_tracking[key]['all_occurrences'].append({
                'source': 'Initial Source Code',
                'line': v.get('line_number'),
                'snippet': v.get('code_snippet', ''),
                'explanation': v.get('explanation', '')
            })
        
        # Add iteration vulnerabilities from custom detector
        for iter_idx, iteration in enumerate(patch_iterations[1:], 1):
            custom_vulns = iteration.get('custom_detector_vulns', {})
            for (cwe_id, cwe_name), vuln_info in custom_vulns.items():
                key = (cwe_id, cwe_name)
                if key not in all_vulns_tracking:
                    all_vulns_tracking[key] = {
                        'cwe_id': cwe_id,
                        'cwe_name': cwe_name,
                        'severity': 'MEDIUM',
                        'description': f'Vulnerability detected in patched code',
                        'explanation': vuln_info.get('explanations', [''])[0] if vuln_info.get('explanations') else '',
                        'patch_note': 'See iteration details',
                        'priority': 'Medium',
                        'initial_count': 0,
                        'iteration_counts': {},
                        'all_lines': [],
                        'all_occurrences': []
                    }
                count = len(vuln_info['lines'])
                all_vulns_tracking[key]['iteration_counts'][iter_idx] = count
                all_vulns_tracking[key]['all_lines'].extend(vuln_info['lines'])
                for i, line in enumerate(vuln_info['lines']):
                    all_vulns_tracking[key]['all_occurrences'].append({
                        'source': f'Patch Iteration {iter_idx}',
                        'line': line,
                        'snippet': '',
                        'explanation': vuln_info['explanations'][i] if i < len(vuln_info['explanations']) else ''
                    })
        
        if all_vulns_tracking:
            # Summary table with initial + iteration tracking
            vuln_data = []
            for key, g in all_vulns_tracking.items():
                # Count total occurrences
                total_occurrences = g['initial_count'] + sum(g['iteration_counts'].values())
                
                # Build found in column
                found_in_parts = []
                if g['initial_count'] > 0:
                    found_in_parts.append("Source code")
                for iter_num in sorted(g['iteration_counts'].keys()):
                    found_in_parts.append(f"Iteration {iter_num}")
                found_in = '; '.join(found_in_parts)
                
                # Get unique sorted lines
                unique_lines = sorted(set(g['all_lines']), key=lambda x: int(x) if str(x).isdigit() else 0)
                lines_str = ', '.join(str(l) for l in unique_lines)
                
                vuln_data.append({
                    'CWE ID': f"CWE-{g['cwe_id']}",
                    'Name': g['cwe_name'],
                    'Severity': g['severity'],
                    'Occurrences': total_occurrences,
                    'Found In': found_in,
                    'Lines': lines_str,
                    'Priority': g['priority']
                })
            
            st.dataframe(vuln_data, use_container_width=True)
            
            # Get iteration code files for showing vulnerable code
            final_reports = results.get('final_reports', {})
            iteration_codes = final_reports.get('iteration_codes', {})
            
            # Enhanced detailed vulnerability view with better organization
            with st.expander("📋 View Detailed Vulnerability Information"):
                for idx, (key, g) in enumerate(all_vulns_tracking.items(), 1):
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
                    
                    # Occurrences by source
                    st.markdown("**Occurrences Details:**")
                    
                    # Group by source and iteration
                    by_source = {}
                    for occ in g['all_occurrences']:
                        source = occ['source']
                        if source not in by_source:
                            by_source[source] = []
                        by_source[source].append(occ)
                    
                    # Display grouped by source with tabs if multiple sources
                    if len(by_source) > 1:
                        tabs = st.tabs(list(by_source.keys()))
                        for tab, (source, occs) in zip(tabs, by_source.items()):
                            with tab:
                                for occ_idx, occ in enumerate(occs, 1):
                                    st.markdown(f"**Line {occ['line']}**")
                                    # Removed explanation display
                                    # Try to get code from iteration file if it's from an iteration
                                    code_shown = False
                                    if 'Iteration' in source and iteration_codes:
                                        import re
                                        iter_match = re.search(r'Iteration (\d+)', source)
                                        if iter_match:
                                            iter_num = iter_match.group(1)
                                            iter_key = f'iteration_{iter_num}'
                                            if iter_key in iteration_codes:
                                                iter_file = iteration_codes[iter_key]
                                                code_context = get_code_from_iteration_file(iter_file, occ['line'], context_lines=3)
                                                if code_context:
                                                    st.code(code_context, language='python')
                                                    code_shown = True
                                    
                                    # Fallback to stored snippet
                                    if not code_shown and occ['snippet']:
                                        st.code(occ['snippet'], language='python')
                    else:
                        # Single source, display directly
                        source = list(by_source.keys())[0]
                        st.markdown(f"*Source: {source}*")
                        for occ_idx, occ in enumerate(by_source[source], 1):
                            st.markdown(f"**{occ_idx}. Line {occ['line']}**")
                            # Removed explanation display
                            # Try to get code from iteration file or original code
                            code_shown = False
                            if 'Iteration' in source and iteration_codes:
                                import re
                                iter_match = re.search(r'Iteration (\d+)', source)
                                if iter_match:
                                    iter_num = iter_match.group(1)
                                    iter_key = f'iteration_{iter_num}'
                                    if iter_key in iteration_codes:
                                        iter_file = iteration_codes[iter_key]
                                        code_context = get_code_from_iteration_file(iter_file, occ['line'], context_lines=3)
                                        if code_context:
                                            st.code(code_context, language='python')
                                            code_shown = True
                            elif 'Initial Source Code' in source:
                                # Show code from original cleaned code
                                original_code = results.get('cleaned_code', results.get('original_code', ''))
                                if original_code:
                                    code_context = get_code_context(original_code, occ['line'], context_lines=3)
                                    if code_context:
                                        st.code(code_context, language='python')
                                        code_shown = True
                            
                            # Fallback to stored snippet
                            if not code_shown and occ['snippet']:
                                st.code(occ['snippet'], language='python')
                    
                    st.markdown("---")
        else:
            st.success("✅ No vulnerabilities detected by Custom Detector!")
        
        # Patched Code
        st.markdown("### ✅ Code Difference")
        
        # Show iteration info
        total_iterations = results.get('total_iterations', 1)
        patch_iterations = results.get('patch_iterations', [])
        final_code = results.get('final_patched_code', results.get('patch_result', {}).get('patched_code', ''))
        bandit_final = results.get('bandit_final', {})
        secondary_final = results.get('secondary_final', {})
        metrics = results.get('metrics', {})
        total_remaining = metrics.get('total_remaining', 0)
        
        if total_remaining == 0:
            st.success("✅ **All vulnerabilities resolved!** This code has 0 issues detected by all three tools.")
        else:
            st.warning(f"⚠️ **{total_remaining} issues remaining** after {total_iterations} iteration(s). Some vulnerabilities could not be automatically fixed.")
        
        if final_code:
            col_before, col_after = st.columns(2)
            
            with col_before:
                st.markdown("#### 📝 Before (Original)")
                st.code(results.get('original_code', ''), language='python', line_numbers=True)
            
            with col_after:
                st.markdown("#### ✨ After (Final Patched)")
                st.code(final_code, language='python', line_numbers=True)
            
            # Changes applied
            changes = results.get('patch_result', {}).get('changes', [])
            col_changes, col_remaining = st.columns(2)
            with col_changes:
                if changes:
                    with st.expander("🔧 View Applied Changes"):
                        # Group changes by CWE and methods only (not by description)
                        grouped_changes = {}
                        for change in changes:
                            cwe_id = change.get('cwe_id', '')
                            cwe_name = change.get('cwe_name', '')
                            detection_method = change.get('detection_method', 'unknown')
                            patch_method = change.get('patch_method', 'unknown')
                            change_desc = change.get('change_description', '')
                            
                            # Create grouping key (without change_description to group similar fixes)
                            key = (cwe_id, cwe_name, detection_method, patch_method)
                            
                            if key not in grouped_changes:
                                grouped_changes[key] = {
                                    'lines': [],
                                    'descriptions': [],
                                    'cwe_id': cwe_id,
                                    'cwe_name': cwe_name,
                                    'detection_method': detection_method,
                                    'patch_method': patch_method
                                }
                            
                            line_num = change.get('line_number')
                            if line_num is not None:
                                grouped_changes[key]['lines'].append(line_num)
                                grouped_changes[key]['descriptions'].append((line_num, change_desc))
                        
                        # Display grouped changes
                        for i, (key, group) in enumerate(grouped_changes.items(), 1):
                            cwe_id = group['cwe_id']
                            cwe_name = group['cwe_name']
                            detection_method = group['detection_method']
                            patch_method = group['patch_method']
                            lines = sorted(set(group['lines']))  # Remove duplicates and sort
                            
                            # Format detection method for display
                            detection_display = {
                                'llm': 'LLM',
                                'pattern': 'Pattern Matching',
                                'ast': 'AST Analysis',
                                'ast-param': 'AST Parameter Analysis',
                                'ast-except': 'AST Exception Analysis',
                                'ast-taint': 'AST Taint Analysis',
                                'similarity': 'Code Similarity',
                                'unknown': 'Unknown'
                            }.get(detection_method, detection_method.upper())
                            
                            patch_display = {
                                'rule-based': 'Rule-Based Patch',
                                'llm-based': 'LLM-Generated Patch',
                                'unknown': 'Unknown'
                            }.get(patch_method, patch_method)
                            
                            # Format line numbers display
                            if len(lines) == 1:
                                lines_text = f"Line {lines[0]}"
                            else:
                                lines_text = f"Lines {', '.join(map(str, lines))}"
                            
                            st.markdown(f"**{i}. CWE-{cwe_id}: {cwe_name}**")
                            st.markdown(f"{lines_text}: Fixed")
                            
                            # Show individual descriptions if they vary
                            if len(set(desc for _, desc in group['descriptions'])) > 1:
                                st.markdown("**Changes:**")
                                for line_num, desc in sorted(group['descriptions']):
                                    st.markdown(f"  - Line {line_num}: {desc}")
                            else:
                                # All descriptions are the same, show just one
                                if group['descriptions']:
                                    st.markdown(f"**Change:** {group['descriptions'][0][1]}")
                            
                            st.markdown(f"_Detected by: {detection_display} | Fixed by: {patch_display}_")
                            st.markdown("---")
            with col_remaining:
                with st.expander("❌ Vulnerabilities Not Fixed After All Iterations"):
                    remaining_vulns = []

                    # Custom detector remaining (final iteration unpatched_vulns)
                    if patch_iterations and patch_iterations[-1].get('unpatched_vulns'):
                        for v in patch_iterations[-1]['unpatched_vulns']:
                            remaining_vulns.append({
                                'Tool': 'Custom Detector',
                                'CWE': v.get('cwe_id', 'N/A'),
                                'Name': v.get('cwe_name', 'Unknown'),
                                'Line': v.get('line_number', 'Unknown'),
                                'Description': v.get('explanation', '')
                            })

                    # Bandit remaining on final code
                    if bandit_final.get('success'):
                        for issue in bandit_final.get('issues', []):
                            remaining_vulns.append({
                                'Tool': 'Bandit',
                                'CWE': issue.get('test_id', 'N/A'),
                                'Name': issue.get('issue_text', issue.get('test_name', 'Bandit Issue')),
                                'Line': issue.get('line_number', 'Unknown'),
                                'Description': issue.get('issue_text', '')
                            })

                    # Semgrep remaining on final code
                    if secondary_final.get('success'):
                        for issue in secondary_final.get('issues', []):
                            lines = issue.get('line_number')
                            line_list = lines if isinstance(lines, list) else ([lines] if lines is not None else [])
                            for line in line_list:
                                remaining_vulns.append({
                                    'Tool': 'Semgrep',
                                    'CWE': issue.get('message_id', issue.get('symbol', 'N/A')),
                                    'Name': issue.get('description', 'Secondary Issue'),
                                    'Line': line,
                                    'Description': issue.get('description', '')
                                })

                    if remaining_vulns:
                        st.dataframe(pd.DataFrame(remaining_vulns), use_container_width=True, hide_index=True)
                    else:
                        st.success("✅ All vulnerabilities were fixed!")
        
        # Static Analysis Results
        st.markdown("### 🔬 Static Analysis Results")
        st.info("ℹ️ Bandit and Semgrep analysis report on both original and iterated patched code.")

        # Static analysis results (show both original and final)
        bandit_original = results.get('bandit_original', {})
        bandit_patched = results.get('bandit_final', results.get('bandit_patched', {}))
        secondary_original = results.get('semgrep_original', results.get('secondary_original', {}))
        secondary_patched = results.get('secondary_final', results.get('secondary_patched', {}))

        col_bandit, col_secondary = st.columns(2)
        
        with col_bandit:
            st.markdown("#### Bandit Analysis")
            original_count = len(bandit_original.get('issues', [])) if bandit_original.get('success') else 0
            final_count = len(bandit_patched.get('issues', [])) if bandit_patched.get('success') else 0
            bandit_total_identified = original_count + final_count
            st.metric("Total Issues", bandit_total_identified)
            if bandit_patched.get('success'):
                patched_count = final_count
                
                if patched_count > 0:
                    # Get iteration code files for context lookup
                    final_reports = results.get('final_reports', {})
                    iteration_codes = final_reports.get('iteration_codes', {})
                    
                    with st.expander(f"🔍 View Bandit Issues - {patched_count}"):
                        for idx, issue in enumerate(bandit_patched.get('issues', []), 1):
                            test_name = issue.get('test_name', issue.get('test_id', 'N/A'))
                            issue_text = issue.get('issue_text', issue.get('description', ''))
                            if not issue_text or issue_text == 'No description':
                                issue_text = test_name
                            st.markdown(f"**{idx}. {issue.get('test_id', 'N/A')}: {issue_text}**")
                            # Severity/Confidence come from Bandit's static analysis output
                            severity = issue.get('issue_severity') or issue.get('severity') or 'MEDIUM'
                            confidence = issue.get('issue_confidence') or issue.get('confidence') or 'MEDIUM'
                            st.markdown(f"- **Severity:** {severity}")
                            st.markdown(f"- **Confidence:** {confidence}")
                            line_num = issue.get('line_number')
                            st.markdown(f"- **Line:** {line_num}")
                            
                            # Try to get code context from iteration file first
                            code_context = ""
                            if iteration_codes and line_num:
                                # Use the last iteration file (most patched version)
                                last_iteration = max(
                                    [k for k in iteration_codes.keys() if k.startswith('iteration_')],
                                    key=lambda x: int(x.split('_')[1]),
                                    default=None
                                )
                                if last_iteration and last_iteration in iteration_codes:
                                    iter_file = iteration_codes[last_iteration]
                                    code_context = get_code_from_iteration_file(iter_file, line_num, context_lines=3)
                            
                            # Fallback to Bandit's provided code snippet if no iteration file context
                            if code_context:
                                st.code(code_context, language='python')
                            elif issue.get('code'):
                                code_snippet = issue.get('code', '')
                                snippet_lines = code_snippet.split('\n')
                                
                                if len(snippet_lines) > 1 and line_num:
                                    # Find which line in the snippet has the vulnerable line number
                                    # Format is "19 sql = ..." (line number, space, then code)
                                    vulnerable_line_index = None
                                    for i, line in enumerate(snippet_lines):
                                        # Check if line starts with the line number followed by space
                                        if line.strip().startswith(f"{line_num} "):
                                            vulnerable_line_index = i + 1  # Convert to 1-indexed
                                            break
                                    
                                    if vulnerable_line_index is None:
                                        # Fallback: if line number not found, assume last non-empty line
                                        for i in range(len(snippet_lines) - 1, -1, -1):
                                            if snippet_lines[i].strip():
                                                vulnerable_line_index = i + 1
                                                break
                                    
                                    # Format the snippet with arrow on vulnerable line
                                    formatted_lines = []
                                    for i, line in enumerate(snippet_lines):
                                        if i + 1 == vulnerable_line_index:
                                            formatted_lines.append("→ " + line)
                                        else:
                                            formatted_lines.append("  " + line)
                                    
                                    st.code('\n'.join(formatted_lines), language='python')
                                else:
                                    st.code(code_snippet, language='python')
                            st.markdown("---")
                else:
                    st.success("✅ No issues found by Bandit!")
            else:
                st.error("❌ Bandit analysis failed")
        
        with col_secondary:
            st.markdown("#### Semgrep Analysis")
            original_count = len(secondary_original.get('issues', [])) if secondary_original.get('success') else 0
            final_count = len(secondary_patched.get('issues', [])) if secondary_patched.get('success') else 0
            semgrep_total_identified = original_count + final_count
            st.metric("Total Issue", semgrep_total_identified)
            if secondary_patched.get('success'):
                patched_count = final_count
                
                if patched_count > 0:
                    with st.expander(f"🔍 View Semgrep Issues - {patched_count}"):
                        # Get patched code from results
                        patched_code = results.get('final_patched_code', results.get('patch_result', {}).get('patched_code', ''))
                        
                        # Debug info
                        if not patched_code:
                            st.warning("⚠️ Code is not available in results")
                        
                        # Group issues by (symbol, message_id, description)
                        grouped_issues = {}
                        for issue in secondary_patched.get('issues', []):
                            key = (issue.get('symbol'), issue.get('message_id'), issue.get('description'), issue.get('type'))
                            if key not in grouped_issues:
                                grouped_issues[key] = []
                            line_num = issue.get('line_number')
                            if line_num is not None:
                                grouped_issues[key].append(line_num)
                        
                        # Display grouped issues
                        for idx, (key, lines) in enumerate(grouped_issues.items(), 1):
                            symbol, msg_id, description, issue_type = key
                            lines = sorted(set(lines))  # Remove duplicates and sort
                            
                            # Use description or fallback to symbol if description is missing
                            display_name = description if description and description != 'Secondary Issue' else symbol
                            st.markdown(f"**{idx}. {issue_type}: {display_name}**")
                            st.markdown(f"- **Symbol:** {symbol}")
                            st.markdown(f"- **Message ID:** {msg_id}")
                            st.markdown(f"- **Lines:** {', '.join(map(str, lines))}")
                            
                            # Show code context for each unique line with arrow pointing to issue
                            if patched_code and lines:
                                for line_num in lines:
                                    try:
                                        context = get_code_context(patched_code, int(line_num), context_lines=2)
                                        if context:
                                            st.code(context, language='python')
                                        else:
                                            st.info(f"No code context available for line {line_num}")
                                    except (ValueError, IndexError, TypeError) as e:
                                        st.error(f"Error getting context for line {line_num}: {str(e)}")
                            elif not patched_code:
                                st.info("Code context unavailable - patched code not found in results")
                            elif not lines:
                                st.info("No valid line numbers found")
                            
                            st.markdown("---")
                else:
                    st.success("✅ No issues found by Semgrep!")
            else:
                st.error("❌ Semgrep analysis failed")

        # Combined vulnerability table from original and all patched iterations
        combined_issues = []

        bandit_original = results.get('bandit_original', {})
        
        # Add vulnerabilities from original code
        if bandit_original.get('success'):
            for issue in bandit_original.get('issues', []):
                lines = issue.get('line_number')
                line_list = [lines] if lines is not None else []
                severity = issue.get('issue_severity') or issue.get('severity', 'UNKNOWN')
                confidence = issue.get('issue_confidence') or issue.get('confidence', 'UNKNOWN')
                combined_issues.append({
                    'ID': issue.get('test_id', 'N/A'),
                    'Name': issue.get('issue_text', issue.get('test_name', 'Bandit Issue')),
                    'Severity': severity,
                    'Confidence': confidence,
                    'Occurrences': len(line_list) if line_list else 1,
                    'Found In': 'Original Code',
                    'Iteration': 'Original'
                })

        # Add vulnerabilities from patched code
        if bandit_patched.get('success'):
            for issue in bandit_patched.get('issues', []):
                lines = issue.get('line_number')
                line_list = [lines] if lines is not None else []
                severity = issue.get('issue_severity') or issue.get('severity', 'UNKNOWN')
                confidence = issue.get('issue_confidence') or issue.get('confidence', 'UNKNOWN')
                # Bandit on patched code is from iteration 1 (first patching round)
                combined_issues.append({
                    'ID': issue.get('test_id', 'N/A'),
                    'Name': issue.get('issue_text', issue.get('test_name', 'Bandit Issue')),
                    'Severity': severity,
                    'Confidence': confidence,
                    'Occurrences': len(line_list) if line_list else 1,
                    'Found In': 'Patched Code (Bandit)',
                    'Iteration': '1'
                })

        # Add vulnerabilities from secondary tool (Semgrep) on patched code
        if secondary_patched.get('success'):
            for issue in secondary_patched.get('issues', []):
                lines = issue.get('line_number')
                line_list = lines if isinstance(lines, list) else ([lines] if lines is not None else [])
                combined_issues.append({
                    'ID': issue.get('message_id', issue.get('symbol', 'N/A')),
                    'Name': issue.get('description', 'Secondary Issue'),
                    'Severity': issue.get('type', issue.get('severity', 'UNKNOWN')),
                    'Confidence': issue.get('confidence', issue.get('severity', 'UNKNOWN')),
                    'Occurrences': len(line_list) if line_list else 1,
                    'Found In': 'Patched Code (Semgrep)',
                    'Iteration': '1'
                })

        if combined_issues:
            st.markdown("### 🔴 Detected Vulnerabilities ")
            # Add SL.No column and remove default index
            df = pd.DataFrame(combined_issues)
            df.insert(0, 'SL.No', range(1, len(df) + 1))
            st.dataframe(df, use_container_width=True, hide_index=True)

        # Get metrics early for use in cross-validation section
        metrics = results.get('metrics', {})
        
        # Tool Comparison and Cross-Validation
        st.markdown("### 🔄 Analysis Summary")
        st.markdown("_Total vulnerabilities from all detection tools across all iterations_")
        
        col_compare1, col_compare2 = st.columns(2)
        
        with col_compare1:
            with st.expander("📊 Total Vulnerabilities Detected"):
                st.markdown("**Across All Iterations (Custom Detector, Bandit, Semgrep):**")
                total_detected = metrics.get('total_detected', 0)
                custom_initial = metrics.get('custom_detector_initial', 0)
                bandit_initial = metrics.get('bandit_initial', 0)
                semgrep_initial = metrics.get('semgrep_initial', 0)
                total_remaining = metrics.get('total_remaining', 0)
                
                st.write(f"- Total detected: **{total_detected}** vulnerabilities")
                st.write(f"- Custom Detector: **{custom_initial}**")
                st.write(f"- Bandit: **{bandit_initial}**")
                st.write(f"- Semgrep: **{semgrep_initial}**")
                st.write(f"\n**Total Remaining: {total_remaining}**")
        
        with col_compare2:
            with st.expander("✅ Issues Resolved by Patching"):
                total_fixed = metrics.get('total_fixed', 0)
                
                st.markdown("**Issues Fixed Across All Iterations:**")
                st.write(f"- Total fixed by system: **{total_fixed}**")
                
                if total_detected > 0:
                    fix_percentage = (total_fixed / total_detected) * 100
                    st.metric("Overall Fix Rate", f"{fix_percentage:.1f}%")
                else:
                    st.metric("Overall Fix Rate", "N/A")
        
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
                'Vulnerabilities Fixed': patching_eff.get('vulnerabilities_fixed', 0),
                'Vulnerabilities Remaining': patching_eff.get('vulnerabilities_remaining', 0)
            }]
            st.table(pd.DataFrame(eff_rows).set_index('Sl.No'))

            st.markdown("#### Tool Comparison")
            comp_rows = [{
                'Sl.No': 1,
                'Bandit Issues': tool_comp.get('primary_tool_issues', 0),
                'Semgrep Issues': tool_comp.get('secondary_tool_issues', 0),
                'Overlapping Detections': tool_comp.get('overlapping_detections', 0),
                'Overlap Rate': f"{tool_comp.get('overlap_rate', 0):.1%}"
            }]
            st.table(pd.DataFrame(comp_rows).set_index('Sl.No'))
        
        # Export Reports
        st.markdown("### 📄 Generated Reports")
        final_reports = results.get('final_reports', {})
        
        if final_reports:
            col1, col2 = st.columns(2)
            
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
        
    def run(self):
        self.render_api_input()
        if st.session_state.api_loaded:
            self.render_main_ui()


if __name__ == "__main__":
    App().run()