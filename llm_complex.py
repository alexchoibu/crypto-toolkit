import ollama
import json
import re


class LLMIdentifier:
    def __init__(self, model: str = "llama3"):
        self.model = model

#Feel free to change the prompt if interested during the Evaluation phase
    def _build_prompt_constrained(self, ciphertext: str, key: str = None) -> str:
        key_section = ""
        if key:
            key_section = f"\nKey (if provided): {key}"

        return f"""You are a cryptanalysis expert. Identify which cryptographic algorithm produced the ciphertext below.

Possible algorithms: 3DES, AES, Base64 to HEX, Base64 to JSON, BLAKE2b, Blowfish, Camellia, ChaCha20, DES, ECC, ElGamal, GOST, MD5, RC4, RSA, Serpent, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, Caesar, single_byte_xor

Hints:
- MD5 hashes are exactly 32 hex characters
- SHA-1 hashes are exactly 40 hex characters
- SHA-224 hashes are exactly 56 hex characters
- SHA-256 hashes are exactly 64 hex characters
- SHA-384 hashes are exactly 96 hex characters
- SHA-512 hashes are exactly 128 hex characters
- SHA3-256 hashes are exactly 64 hex characters (same length as SHA-256 but different values)
- BLAKE2b hashes are long hex strings up to 128 hex characters
- Base64 to HEX means the output is a Base64 encoded hex string
- Base64 to JSON means the output is a Base64 encoded JSON structure
- RSA/ECC/ElGamal ciphertexts are very long base64 or hex strings
- AES/DES/3DES/Blowfish/Camellia/Serpent are block ciphers, outputs are base64 or hex blobs
- ChaCha20 and RC4 are stream ciphers, outputs look like random hex or base64
- GOST is a Russian symmetric block cipher, output resembles AES
- Caesar ciphertexts look like readable but letter-shifted English text
- single_byte_xor ciphertexts are hex strings the same byte-length as the original plaintext

Ciphertext: {ciphertext}{key_section}

Respond only with this exact JSON format, no markdown, no explanation:
{{"algorithm": "algorithm name here", "reasoning": "one sentence explanation"}}"""
#This one below is for Llama without the algorithm hints above. Can Llama figure out what possible cryptographic algorithm is being inputted?
    def _build_prompt_unconstrained(self, ciphertext: str) -> str:
        return f"""You are a cryptanalysis expert. Identify which cryptographic algorithm produced the ciphertext below. You may name any algorithm you believe is correct. Do not limit yourself to any predefined list.

Ciphertext: {ciphertext}

Respond only with this exact JSON format, no markdown, no explanation:
{{"algorithm": "algorithm name here", "reasoning": "one sentence explanation"}}"""

    #Parsing

    def _parse_response(self, raw: str) -> dict:
        match = re.search(r'\{.*?\}', raw, re.DOTALL)
        if not match:
            raise ValueError(f"No JSON object found in LLM response: {raw}")
        return json.loads(match.group(0))
    

    def identify_constrained(self, ciphertext: str) -> dict:
        prompt = self._build_prompt_constrained(ciphertext)
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return self._parse_response(response["message"]["content"])

    def identify_constrained_with_key(self, ciphertext: str, key: str) -> dict:
        prompt = self._build_prompt_constrained(ciphertext, key=key)
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return self._parse_response(response["message"]["content"])

    def identify_unconstrained(self, ciphertext: str) -> dict:
        prompt = self._build_prompt_unconstrained(ciphertext)
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return self._parse_response(response["message"]["content"])
