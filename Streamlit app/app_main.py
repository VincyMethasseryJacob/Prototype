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
                    max_patch_iterations=3
                )
            except Exception:
                st.session_state.api_loaded = False
                self.client_wrapper = None
                self.workflow = None

    def _ensure_session(self):
        defaults = {
            "api_loaded": False,
            "api_key": "",
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
                        st.success("API key validated! Loading application…")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to initialize OpenAI client: {e}")

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
                    if workflow_result.get('vulnerability_count', 0) > 0:
                        st.session_state.show_analysis_view = True
                        st.rerun()
                    self._display_workflow_results(workflow_result)
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

    # -------------------- DATASET UI --------------------
    def _ui_dataset_prompt(self, wide=False):
        mp = st.session_state.securityeval_map
        if not mp:
            st.info("Dataset folder is empty.")
            return
        selected = st.selectbox("Select sample:", list(mp.keys()), key="dataset_select")
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
                    if workflow_result.get('vulnerability_count', 0) > 0:
                        st.session_state.show_analysis_view = True
                        st.rerun()
                    self._display_workflow_results(workflow_result)
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
            st.markdown("## 🔍 Vulnerability Analysis Results")
        else:
            st.markdown("### 🔍 Vulnerability Analysis Results")
        
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
            st.metric("Vulnerabilities Found", results.get('vulnerability_count', 0))
        with col2:
            vulns_fixed = results.get('vulnerability_count', 0) - len(results.get('patch_result', {}).get('unpatched_vulns', []))
            st.metric("Vulnerabilities Fixed", vulns_fixed)
        with col3:
            st.metric("Patch Iterations", results.get('total_iterations', 0))
        with col4:
            success_rate = results.get('metrics', {}).get('overall_success_rate', 0)
            st.metric("Success Rate", f"{success_rate:.1%}")
        
        # Detected Vulnerabilities
        st.markdown("### 🔴 Detected Vulnerabilities")
        vulns = results.get('vulnerabilities_with_explanations', [])
        
        if vulns:
            # Group vulnerabilities by CWE to avoid repeating descriptions
            grouped = {}
            for v in vulns:
                cid = v.get('cwe_id')
                if cid not in grouped:
                    grouped[cid] = {
                        'cwe_id': cid,
                        'cwe_name': v.get('cwe_name'),
                        'severity': v.get('severity'),
                        'description': v.get('description'),
                        'explanation': v.get('explanation'),
                        'patch_note': v.get('patch_note'),
                        'priority': v.get('remediation_priority'),
                        'lines': [],
                        'snippets': []
                    }
                grouped[cid]['lines'].append(v.get('line_number'))
                if v.get('code_snippet'):
                    grouped[cid]['snippets'].append(v.get('code_snippet'))

            # Summary table: one row per CWE
            vuln_data = []
            for g in grouped.values():
                vuln_data.append({
                    'CWE ID': f"CWE-{g['cwe_id']}",
                    'Name': g['cwe_name'],
                    'Severity': g['severity'],
                    'Lines': ', '.join(str(l) for l in sorted(g['lines'])),
                    'Priority': g['priority']
                })
            st.dataframe(vuln_data, use_container_width=True)

            # Detailed grouped vulnerability info
            with st.expander("📋 View Detailed Vulnerability Information"):
                for idx, g in enumerate(grouped.values(), 1):
                    st.markdown(f"#### {idx}. CWE-{g['cwe_id']}: {g['cwe_name']}")
                    st.markdown(f"**Severity:** {g['severity']} | **Lines:** {', '.join(str(l) for l in sorted(g['lines']))} | **Priority:** {g['priority']}")
                    st.markdown(f"**Description:** {g['description']}")
                    st.markdown(f"**Explanation:** {g['explanation']}")
                    st.markdown(f"**Patch Recommendation:** {g['patch_note']}")
                    if g['snippets']:
                        for s in g['snippets'][:3]:  # limit to first 3 snippets
                            st.code(s, language='python')
                    st.markdown("---")
        
        # Patched Code
        st.markdown("### ✅ Patched Code")
        final_code = results.get('final_patched_code', results.get('patch_result', {}).get('patched_code', ''))
        
        if final_code:
            col_before, col_after = st.columns(2)
            
            with col_before:
                st.markdown("#### Before (Original)")
                st.code(results.get('original_code', ''), language='python', line_numbers=True)
            
            with col_after:
                st.markdown("#### After (Patched)")
                st.code(final_code, language='python', line_numbers=True)
            
            # Changes applied
            changes = results.get('patch_result', {}).get('changes', [])
            if changes:
                with st.expander("🔧 View Applied Changes"):
                    for i, change in enumerate(changes, 1):
                        cwe_id = change.get('cwe_id', '')
                        cwe_name = change.get('cwe_name', '')
                        detection_method = change.get('detection_method', 'unknown')
                        patch_method = change.get('patch_method', 'unknown')
                        
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
                        
                        st.markdown(f"**{i}. CWE-{cwe_id}: {cwe_name}**")
                        st.markdown(f"Line {change.get('line_number')}: {change.get('change_description')}")
                        st.markdown(f"_Detected by: {detection_display} | Fixed by: {patch_display}_")
                        st.markdown("---")
        
        # Static Analysis Results
        st.markdown("### 🔬 Static Analysis Results")
        
        bandit_original = results.get('bandit_original', {})
        bandit_patched = results.get('bandit_patched', {})
        secondary_original = results.get('secondary_original', {})
        secondary_patched = results.get('secondary_patched', {})
        
        col_bandit, col_secondary = st.columns(2)
        
        with col_bandit:
            st.markdown("#### Bandit Analysis")
            if bandit_original.get('success'):
                original_count = len(bandit_original.get('issues', []))
                patched_count = len(bandit_patched.get('issues', []))
                st.metric("Issues Identified (Source Code)", original_count)
                st.metric("Issues Identified (Patched Code)", patched_count, delta=-(original_count - patched_count))
                
                if bandit_patched.get('summary'):
                    severity = bandit_patched['summary'].get('severity_breakdown', {})
                    st.write("Severity Breakdown (Patched):")
                    for sev, count in severity.items():
                        if count > 0:
                            st.write(f"- {sev}: {count}")
                
                # Show detailed issues found by Bandit
                if original_count > 0:
                    with st.expander(f"🔍 View Bandit Issues in Original Code ({original_count})"):
                        for idx, issue in enumerate(bandit_original.get('issues', []), 1):
                            st.markdown(f"**{idx}. {issue.get('test_id', 'N/A')}: {issue.get('issue_text', 'No description')}**")
                            st.markdown(f"- **Severity:** {issue.get('issue_severity', 'UNKNOWN')}")
                            st.markdown(f"- **Confidence:** {issue.get('issue_confidence', 'UNKNOWN')}")
                            st.markdown(f"- **Line:** {issue.get('line_number', 'N/A')}")
                            if issue.get('code'):
                                st.code(issue.get('code'), language='python')
                            st.markdown("---")
                
                if patched_count > 0:
                    with st.expander(f"🔍 View Bandit Issues in Patched Code ({patched_count})"):
                        for idx, issue in enumerate(bandit_patched.get('issues', []), 1):
                            st.markdown(f"**{idx}. {issue.get('test_id', 'N/A')}: {issue.get('issue_text', 'No description')}**")
                            st.markdown(f"- **Severity:** {issue.get('issue_severity', 'UNKNOWN')}")
                            st.markdown(f"- **Confidence:** {issue.get('issue_confidence', 'UNKNOWN')}")
                            st.markdown(f"- **Line:** {issue.get('line_number', 'N/A')}")
                            if issue.get('code'):
                                st.code(issue.get('code'), language='python')
                            st.markdown("---")
                
                # Show resolved issues
                resolved_count = original_count - patched_count
                if resolved_count > 0:
                    st.success(f"✅ {resolved_count} Bandit issue(s) resolved by patching!")
        
        with col_secondary:
            st.markdown("#### Pylint Analysis")
            if secondary_original.get('success'):
                original_count = len(secondary_original.get('issues', []))
                patched_count = len(secondary_patched.get('issues', []))
                st.metric("Issues Identified (Source Code)", original_count)
                st.metric("Issues Identified (Patched Code)", patched_count, delta=-(original_count - patched_count))
                
                # Show detailed issues found by Pylint
                if original_count > 0:
                    with st.expander(f"🔍 View Pylint Issues in Original Code ({original_count})"):
                        for idx, issue in enumerate(secondary_original.get('issues', []), 1):
                            st.markdown(f"**{idx}. {issue.get('type', 'N/A')}: {issue.get('message', 'No description')}**")
                            st.markdown(f"- **Symbol:** {issue.get('symbol', 'N/A')}")
                            st.markdown(f"- **Line:** {issue.get('line', 'N/A')}")
                            st.markdown("---")
                
                if patched_count > 0:
                    with st.expander(f"🔍 View Pylint Issues in Patched Code ({patched_count})"):
                        for idx, issue in enumerate(secondary_patched.get('issues', []), 1):
                            st.markdown(f"**{idx}. {issue.get('type', 'N/A')}: {issue.get('message', 'No description')}**")
                            st.markdown(f"- **Symbol:** {issue.get('symbol', 'N/A')}")
                            st.markdown(f"- **Line:** {issue.get('line', 'N/A')}")
                            st.markdown("---")
                
                # Show resolved issues
                resolved_count = original_count - patched_count
                if resolved_count > 0:
                    st.success(f"✅ {resolved_count} Pylint issue(s) resolved by patching!")
        
        # Get metrics early for use in cross-validation section
        metrics = results.get('metrics', {})
        
        # Tool Comparison and Cross-Validation
        st.markdown("### 🔄 Tool Cross-Validation")
        st.markdown("_Comparing what different tools detected in the analysis_")
        
        col_compare1, col_compare2 = st.columns(2)
        
        with col_compare1:
            with st.expander("📊 Tool Detection Comparison"):
                st.markdown("**Detection Coverage:**")
                custom_vuln_count = len(results.get('vulnerabilities_detected', []))
                bandit_orig_count = len(bandit_original.get('issues', []))
                pylint_orig_count = len(secondary_original.get('issues', []))
                
                st.write(f"- Custom Detector: **{custom_vuln_count}** vulnerabilities")
                st.write(f"- Bandit: **{bandit_orig_count}** issues")
                st.write(f"- Pylint: **{pylint_orig_count}** issues")
                
                if metrics.get('tool_comparison'):
                    tool_comp = metrics['tool_comparison']
                    overlap = tool_comp.get('overlapping_detections', 0)
                    st.write(f"\n**Overlap:** {overlap} issues detected by multiple tools")
        
        with col_compare2:
            with st.expander("✅ Issues Resolved by Patching"):
                custom_fixed = len(results.get('vulnerabilities_detected', [])) - len(results.get('patch_result', {}).get('unpatched_vulns', []))
                bandit_fixed = len(bandit_original.get('issues', [])) - len(bandit_patched.get('issues', []))
                pylint_fixed = len(secondary_original.get('issues', [])) - len(secondary_patched.get('issues', []))
                
                st.markdown("**Issues Fixed by Patching:**")
                st.write(f"- Custom Detector vulnerabilities: **{custom_fixed}** fixed")
                st.write(f"- Bandit issues: **{bandit_fixed}** fixed")
                st.write(f"- Pylint issues: **{pylint_fixed}** fixed")
        
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
                'Pylint Issues': tool_comp.get('secondary_tool_issues', 0),
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
                if 'initial_reports' in results:
                    reports = results['initial_reports']
                    if reports.get('csv_path'):
                        st.markdown(f"📋 [Vulnerability Report (CSV)]({reports['csv_path']})")
                    if reports.get('json_path'):
                        st.markdown(f"📋 [Vulnerability Report (JSON)]({reports['json_path']})")
            
            with col2:
                if final_reports.get('patch_report'):
                    patch_rep = final_reports['patch_report']
                    if patch_rep.get('report_path'):
                        st.markdown(f"🔧 [Patch Report]({patch_rep['report_path']})")
                    if patch_rep.get('diff_path'):
                        st.markdown(f"🔧 [Code Diff]({patch_rep['diff_path']})")
            
            with col3:
                if final_reports.get('metrics'):
                    st.markdown(f"📊 [Metrics Report]({final_reports['metrics']})")
                if final_reports.get('html_summary'):
                    st.markdown(f"📄 [HTML Summary]({final_reports['html_summary']})")

    def run(self):
        self.render_api_input()
        if st.session_state.api_loaded:
            self.render_main_ui()


if __name__ == "__main__":
    App().run()