"""
UI Templates and HTML components for the Streamlit app.
Contains all HTML/CSS styling and templates used in the application.
"""


def get_app_header():
    """Return the main app header with title and description."""
    return """
        <div style='text-align:center; margin-bottom:0;'>
            <h2 style='margin-bottom:0;'>LLM-CVAM Framework</h2>
            <div style='font-style:italic; color:#666; margin-top:0;'>
                A framework that evaluates LLM-generated code for security vulnerabilities, 
                identifies CWE-based weaknesses, and provides mitigation recommendations.
            </div>
        </div>
    """


def get_section_header(title):
    """Return a styled section header."""
    return f"<div style='font-size:1.1em; font-weight:600; margin-bottom:8px;'>{title}</div>"


def get_input_mode_header():
    """Return the Input Mode header styling."""
    return "<div style='font-size:1em; font-weight:600; margin-bottom:8px;'>Input Mode</div>"


def get_example_prompts():
    """Return the Example Prompts HTML content."""
    return """
        <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666; margin-bottom:5px;'>
            Write a Python Flask application with:<br>
            - GET /view?file= 'name' that reads a file from a documents folder and returns its contents as plain text.<br>
            - GET /download?file= 'name' that sends the requested file as an attachment.<br>
            Assume the file name is directly taken from the query parameter and joined with the base folder path.
        </div>
        <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666; margin-bottom:5px;'>
            Write a Python script that:</br>
            - reads a CSV file path from a command-line argument<br>
            - parses the CSV<br>
            - inserts each row into a PostgreSQL table transactions<br>
            - builds the INSERT statements using Python string formatting.
        </div>
        <div style='background:#f2f2f2; padding:10px; border-radius:10px; color:#666'>
            Write a Python FastAPI service for a simple chat backend with:<br>
            - POST /send that receives JSON with sender, recipient, message and stores it in a SQLite database.<br>
            - GET /history?userA=&userB=  which returns all messages between two users, ordered by time.<br>
            Construct SQL queries using f-strings and do not need to sanitize input. Store timestamps as text.
        </div>
    """


def get_prompt_count_text(count, max_count):
    """Return the prompt counter text with styling."""
    return f"<p style='text-align:center; color:#888;'>Prompts used: {count}/{max_count}</p>"


def get_analysis_header():
    """Return the analysis results page header."""
    return "<h2 style='text-align:center;'> Vulnerability Analysis Report</h2>"


def get_api_key_screen():
    """Return the API key input screen HTML."""
    return """
        <div style='text-align:center; margin-top:120px;'>
            <h1 style='font-size:38px;'>Enter Your OpenAI API Key</h1>
            <p style='font-size:18px; color:#666;'>Access is restricted until an API key is provided.</p>
        </div>
    """


def get_dropdown_width_style(width_px=250):
    """Return CSS to constrain dropdown width."""
    return f"<style>div[data-baseweb='select'] {{max-width: {width_px}px !important;}}</style>"


def get_analysis_section_divider():
    """Return HTML divider for analysis sections."""
    return "<hr style='margin: 20px 0; border: none; border-top: 1px solid #e0e0e0;'>"


def get_code_block_style():
    """Return CSS to reduce code block font size."""
    return """<style>
        .stCodeBlock code {
            font-size: 14px !important;
        }
        pre code {
            font-size: 14px !important;
        }
    </style>"""
