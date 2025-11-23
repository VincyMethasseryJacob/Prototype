import os
import re
import datetime
import streamlit as st
from services import (
    SecurityEvalLoader,
    CWEFetcher,
    AuditManager,
    OpenAIClientWrapper,
)

# Directories
TESTCASES_DIR = r"D:\Vincy-Certificates\AIDA\Winter'25\Thesis\Prototype\SecurityEval-main\Testcases_Prompt"
AUDIT_DIR = os.path.join(os.path.dirname(__file__), "audit_records")

# Limits
MAX_PROMPTS = 5
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

        if st.session_state.get("api_loaded") and st.session_state.get("api_key"):
            try:
                self.client_wrapper = OpenAIClientWrapper(st.session_state["api_key"])
            except Exception:
                st.session_state.api_loaded = False
                self.client_wrapper = None

    def _ensure_session(self):
        defaults = {
            "api_loaded": False,
            "api_key": "",
            "securityeval_map": {},
            "prompt_count": 0,
            "active_prompt": "",
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
            st.markdown(
                """
                <div style='text-align:center; margin-top:120px;'>
                    <h1 style='font-size:38px;'>Enter Your OpenAI API Key</h1>
                    <p style='font-size:18px; color:#666;'>Access is restricted until an API key is provided.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

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

        left, center, right = st.columns([0.25, 0.5, 0.25])
        with center:
            # Heading
            st.markdown(
                "<h2 style='text-align:center;'>LLM Code Vulnerability Analyzer & Mitigation Framework</h2>",
                unsafe_allow_html=True,
            )
            # Description
            st.markdown(
                """
                <p style='text-align:center; font-style:italic; color:#666;'>
                    A framework that evaluates LLM-generated code for security vulnerabilities,
                    identifies CWE-based weaknesses, and provides mitigation recommendations.
                </p>
                """,
                unsafe_allow_html=True,
            )

            option = st.radio(
                "Choose input method:",
                ("Enter new prompt", "Choose from dataset"),
                horizontal=True,
            )

            if option == "Enter new prompt":
                self._ui_new_prompt()
            else:
                self._ui_dataset_prompt()

            st.markdown(
                f"<p style='text-align:center; color:#888;'>Prompts used: {st.session_state.prompt_count}/{MAX_PROMPTS}</p>",
                unsafe_allow_html=True,
            )

    # -------------------- NEW PROMPT UI --------------------
    def _ui_new_prompt(self):
        prompt = st.text_area(
            "Enter the prompt (Python code tasks only):",
            height=300,
            value=st.session_state.active_prompt,
        )

        st.markdown(
            """
            <div style='margin-top:10px;'>
                <p><b>Example prompts:</b></p>
                <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666; margin-bottom:5px;'>
                    Fix this buffer overflow and return code only.
                </div>
                <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666; margin-bottom:5px;'>
                    Refactor to parameterized queries. Return code only.
                </div>
                <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666'>
                    Sanitize user input. Return only code patch.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # One line divider for spacing
        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        if st.button("Generate", use_container_width=True):
            if st.session_state.prompt_count >= MAX_PROMPTS:
                st.warning("Maximum prompts (5) reached.")
                return
            if not prompt.strip():
                st.warning("Please enter a prompt.")
                return

            text = self.client_wrapper.generate_code_only_response(
                prompt, max_tokens=MAX_RESPONSE_TOKENS
            )
            st.session_state.active_prompt = prompt
            st.session_state.prompt_count += 1

            st.markdown("### Response")
            st.code(text, language="python")

            self.audit.save(
                {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "workflow": "new_prompt",
                    "prompt": prompt,
                    "response": text,
                    "prompt_count": st.session_state.prompt_count,
                }
            )

    # -------------------- DATASET UI --------------------
    def _ui_dataset_prompt(self):
        mp = st.session_state.securityeval_map

        if not mp:
            st.info("Dataset folder is empty.")
            return

        selected = st.selectbox("Select sample:", list(mp.keys()))
        entry = mp[selected]
        content = entry["content"]
        path = entry["path"]

        st.markdown("#### Short Description")
        st.write(self._extract_short_description(content))

        cwe_id = CWEFetcher.extract_cwe_id(content)
        if cwe_id:
            desc = CWEFetcher.fetch_description(cwe_id)
            st.markdown(f"#### CWE {cwe_id} Description")
            st.write(desc)

        with st.expander("Show file content"):
            st.code(content, language="python")

        if st.button("Generate from this sample", use_container_width=True):
            if st.session_state.prompt_count >= MAX_PROMPTS:
                st.warning("Maximum prompts reached.")
                return

            text = self.client_wrapper.generate_code_only_response(
                content,
                max_tokens=MAX_RESPONSE_TOKENS,
                allow_non_code_prompt=True,
                enforce_input_limit=False  
        )
            st.session_state.prompt_count += 1

            st.markdown("### Response")
            st.code(text, language="python")

            self.audit.save(
                {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "workflow": "dataset_prompt",
                    "file": selected,
                    "content": content,
                    "cwe_id": cwe_id,
                    "response": text,
                    "prompt_count": st.session_state.prompt_count,
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

    def run(self):
        self.render_api_input()
        if st.session_state.api_loaded:
            self.render_main_ui()


if __name__ == "__main__":
    App().run()