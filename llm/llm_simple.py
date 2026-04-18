import ollama
import json
import re


class LLMDecryption:
    def __init__(self, model: str = "llama3"):
        self.model = model
        
    #Emily, feel free to change the prompt as you see fit during evaluation in case you're interested in evaluating what prompt works best, or whether it doesn't change anything at all
    def _build_prompt(self, ciphertext: str) -> str:
        #I used roleplaying here
        return f"""You are a cryptanalysis expert. Identify whether the ciphertext below used a Caesar cipher or single-byte XOR cipher, then decrypt it.

Rules:
- "caesar": letters are shifted by a fixed amount (key = 1-25). Input looks like readable but garbled text.
- "single_byte_xor": each byte XORed with a single key byte (key = 0-255). Input looks like a hex string (e.g. "4a6f686e").

To decrypt:
- Caesar: try all 25 shifts, pick the most readable English result.
- XOR: decode hex to bytes, try all 256 keys, decode as UTF-8, pick most readable English result.

Ciphertext: {ciphertext}

Respond ONLY with this exact JSON format, no markdown, no explanation:
{{"algorithm": "caesar" or "single_byte_xor", "plaintext": "decrypted text here", "key": <integer>}}"""

    def decrypt(self, ciphertext: str) -> tuple:
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": self._build_prompt(ciphertext)}]
        )

        raw = response["message"]["content"]

        # Clean up any accidental markdown fences
        cleaned = re.sub(r"```[a-z]*", "", raw).strip()

        parsed = json.loads(cleaned)
        return parsed["algorithm"].strip().lower(), parsed["plaintext"], int(parsed["key"])
