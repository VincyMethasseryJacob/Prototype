import os

class SecurityEvalLoader:
    """
    Load pre-written prompt files from the SecurityEval dataset.
    
    """

    @staticmethod
    def load_prompts(base_dir: str) -> dict:
        prompts_map = {}

        if not os.path.isdir(base_dir):
            return prompts_map

        for root, _, files in os.walk(base_dir):
            for fname in files:
                if fname.lower().startswith("author") and fname.lower().endswith(".py"):
                    full = os.path.join(root, fname)
                    try:
                        with open(full, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if content:
                                rel = os.path.relpath(full, base_dir).replace(os.sep, "/")
                                prompts_map[rel] = {
                                    "path": full,
                                    "content": content,
                                }
                    except Exception:
                        # Ignore malformed or unreadable files
                        continue

        return prompts_map