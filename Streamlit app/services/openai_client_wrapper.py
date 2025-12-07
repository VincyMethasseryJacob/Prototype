from openai import OpenAI

# Maximum tokens allowed for response
MAX_RESPONSE_TOKENS_DEFAULT = 5000


class OpenAIClientWrapper:
    """
    Wrapper around the OpenAI API with strict restrictions:
    """

    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """
        Validate the OpenAI API key by making a minimal API call.
        Returns True if valid, False otherwise.
        """
        try:
            client = OpenAI(api_key=api_key.strip())
            # Minimal call: list models (safe, fast, doesn't use tokens)
            _ = client.models.list()
            return True
        except Exception:
            return False

    def __init__(self, api_key: str):
        if not api_key or not api_key.strip():
            raise ValueError("API key is required.")
        self.client = OpenAI(api_key=api_key.strip())

    @staticmethod
    def _is_code_generation_prompt(prompt: str) -> bool:
        """
        Detect if the user intends to generate Python code.
        If not, the system should refuse the request.
        """
        keywords = ["code", "python", "function", "class", "refactor", "fix", "patch"]
        prompt_lower = prompt.lower()
        return any(k in prompt_lower for k in keywords)

    @staticmethod
    def _token_estimate(text: str) -> int:
        """
        Rough estimation of tokens.
        Rule of thumb: 1 token ≈ 4 characters.
        """
        return max(1, len(text) // 4)

    def generate_code_only_response(self, prompt: str, max_tokens: int = MAX_RESPONSE_TOKENS_DEFAULT,
        allow_non_code_prompt: bool = False, enforce_input_limit: bool = True,) -> str:
        """
        Generates a Python-only code response.
        Rejects prompts that do not match the allowed format.
        Performs token limit checks.
        """

        # 1. Enforce: prompt must be about code
        if not allow_non_code_prompt and not self._is_code_generation_prompt(prompt):
            return (
                " This LLM is restricted to generating Python code only. "
                "Your request does not appear to be code-related."
            )

        # 2. Enforce: prompt token length <= 5000
        if enforce_input_limit:
            est_tokens = self._token_estimate(prompt)
            if est_tokens > 5000:
                return (
                f" Entered Prompt is too long. Estimated token count {est_tokens}/5000. "
                "Reduce your prompt length."
            )

        # 3. System message (strict)
        system_msg = {
            "role": "system",
            "content": (
                "You are an assistant that ONLY return Python code. "
                "NO explanations, NO comments, NO plain text. Return strictly code."
            ),
        }

        user_msg = {"role": "user", "content": prompt}

        # 4. Call OpenAI API
        resp = self.client.chat.completions.create(
            model="gpt-4.1",
            messages=[system_msg, user_msg],
            max_tokens=max_tokens
        )
        try:
            return resp.choices[0].message.content
        except Exception:
            return str(resp)