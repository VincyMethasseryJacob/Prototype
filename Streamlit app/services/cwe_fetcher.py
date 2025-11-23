import re
import requests

class CWEFetcher:
    """
    Extract CWE ID from prompt text and fetch the description
    directly from the MITRE CWE website.
    """

    # Matches patterns like:
    #   CWE-020, CWE 20, CWE:020, CWE00020
    CWE_REGEX = re.compile(r"CWE[-\s:]*0*([0-9]+)\b", flags=re.IGNORECASE)

    @staticmethod
    def extract_cwe_id(content: str) -> str | None:
        """
        Extract the numeric CWE ID from content.
        Removes leading zeros and returns pure number as a string.
        """
        m = CWEFetcher.CWE_REGEX.search(content)
        if not m:
            return None

        try:
            # Convert to int → removes leading zeros
            num = int(m.group(1))
            return str(num)
        except Exception:
            # Fallback if conversion fails
            return m.group(1).lstrip("0") or None

    @staticmethod
    def fetch_description(cwe_id: str) -> str:
        """
        Fetches the CWE description from MITRE
        
        """
        if not cwe_id or not cwe_id.isdigit():
            return "CWE ID not available."

        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

        try:
            resp = requests.get(url, timeout=8)

            if resp.status_code != 200:
                return "CWE description not found on the CWE site."

            html = resp.text

            # Extracts the main CWE description block
            match = re.search(r'<div[^>]*class="cwe-description"[^>]*>(.*?)</div>', html, flags=re.S | re.I)

            if not match:
                return "CWE description not found on the CWE site."

            raw_block = match.group(1)

            # Remove HTML tags
            cleaned = re.sub(r"<[^>]+>", "", raw_block)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()

            return cleaned

        except Exception as e:
            return f"Error fetching CWE description: {e}"