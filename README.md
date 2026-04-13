# Automated Cryptanalysis and Cryptographic Algorithm Identification Toolkit

A Python toolkit that automatically identifies and analyzes cryptographic artifacts — encrypted text, encoded data, and hash outputs — and compares rule-based heuristic detection against LLM-assisted analysis.

## Team

| Name | Role |
|------|------|
| Alex | Data pipeline — dataset download, cleaning, hash dataset generation |
| Nare | Baseline artifact identifier — encoding and hash detection |
| Selman | Baseline cryptanalysis — Caesar and single-byte XOR decryption |
| Princessa | LLM integration — local Llama model, prompt engineering |
| Emily | Evaluation & comparison — benchmarking framework, results |

---

## Project Structure

```
crypto-toolkit/
├── baseline/                        # Rule-based artifact identifier (Nare)
│   ├── __init__.py
│   ├── artifact_identifier.py       # ArtifactIdentifier class — main detector
│   └── evaluate_identifier.py       # Evaluation against all three datasets
│
├── base_decryption/                 # Cryptanalysis module (Selman)
│   ├── base_decryption.py           # Caesar and single-byte XOR decryption
│   ├── cipher_dataset_generator.py  # Generates data/cipher_dataset.csv
│   ├── sentences.txt                # Plaintext source (SecLists)
│   ├── wordlist.txt                 # English wordlist for scoring
│   └── 1-1000.txt                   # Top-1000 common English words
│
├── data/
│   ├── generate_hash_dataset.py     # Script to regenerate hash_dataset.csv
│   ├── cipher_dataset.csv           # Generated Caesar/XOR dataset
│   ├── hash_dataset.csv             # Generated MD5/SHA-1/SHA-256 dataset (gitignored)
│   └── dataset.csv                  # Kaggle classification dataset (gitignored)
│
├── llm/                             # LLM integration (Princessa) — coming soon
├── evaluation/                      # Cross-module benchmarking (Emily) — coming soon
│
├── test_baseline.py                 # Quick smoke test for cryptanalysis module
└── README.md
```

---

## Datasets

### 1. Cipher Dataset — `data/cipher_dataset.csv`
Generated in-repo from `base_decryption/sentences.txt` (SecLists).
Contains ~10,000 rows of Caesar and single-byte XOR ciphertexts with ground-truth keys.

**Regenerate:**
```bash
python3 -c "from base_decryption.cipher_dataset_generator import create_cipher_dataset; create_cipher_dataset()"
```

### 2. Hash Dataset — `data/hash_dataset.csv`
500 MD5 + 500 SHA-1 + 500 SHA-256 digests from SecLists sentences. Gitignored (regenerate locally).

**Regenerate:**
```bash
python3 data/generate_hash_dataset.py
```

### 3. Kaggle Classification Dataset — `data/dataset.csv`
220,000+ rows covering AES, DES, RSA, RC4, ChaCha20, MD5, SHA-*, and more.
Download from: https://www.kaggle.com/datasets/chaitanya205/cryptographic-algorithm-classification-dataset  
Place the downloaded CSV at `data/dataset.csv`.

---

## Baseline Artifact Identifier

The `baseline/artifact_identifier.py` module detects cryptographic artifact types using structural heuristics and information-theoretic features (Shannon entropy, printable-byte ratio, text readability). No keys or decryption are required.

### Supported artifact types

| Type | Algorithms detected |
|------|-------------------|
| **Hash** | MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |
| **Encoding** | Base64, Base64-URL, Base32, Hex |
| **Classical cipher** | Caesar, Single-byte XOR |
| **Modern cipher (heuristic)** | AES, DES/3DES/Blowfish, RC4/stream, RSA |

### Quick start

```python
from baseline.artifact_identifier import ArtifactIdentifier

ai = ArtifactIdentifier()

# Hash detection
r = ai.identify("d41d8cd98f00b204e9800998ecf8427e")
# IdentificationResult(artifact_type='hash', algorithm='MD5', confidence=0.75)

# Base64 encoding
r = ai.identify("SGVsbG8gV29ybGQ=")
# IdentificationResult(artifact_type='encoding', algorithm='Base64', confidence=0.78)

# Caesar cipher
r = ai.identify("Pdau zayezaz pk lhwjp wj knydwnz kb ykppkj ywjzu.")
# IdentificationResult(artifact_type='cipher', algorithm='Caesar', confidence=0.70)

# Batch mode
results = ai.identify_batch(["48656c6c6f", "SGVsbG8=", "e3b0c44298fc..."])
```

### Detection logic

Detectors run in priority order; the first result with confidence ≥ 0.88 short-circuits the pipeline:

1. **RSA** — long Base64 (≥ 300 chars) with near-maximum decoded byte entropy
2. **Hash** — exact hex digest length + Shannon entropy gate (rejects XOR ciphertexts of same length)
3. **Base32** — restricted charset `[A-Z2-7=]` + valid decode
4. **Caesar** — alpha/punctuation only, letter entropy in [3.5, 4.8], low English-word score
5. **Hex encoding** — high printable ratio AND high word-readability in decoded bytes
6. **Single-byte XOR** — even-length hex, high byte entropy, not pure-readable
7. **Hex cipher** — block-aligned high-entropy hex (AES=16-byte blocks, DES=8-byte, RC4=other)
8. **Base64** — standard/URL-safe, excludes pure-hex strings (sent to detectors above)

---

## Evaluation Results

Run with: `python3 baseline/evaluate_identifier.py` from the repo root.

| Dataset | Task | Accuracy |
|---------|------|----------|
| Custom hash dataset (A) | MD5 / SHA-1 / SHA-256 | **99.07%** |
| Kaggle dataset (B) — hash rows | MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 | **75.2%** |
| Kaggle dataset (B) — cipher rows (resolvable) | RSA, RC4-family | ~30% |
| Classical cipher dataset (C) | Caesar / SingleByteXOR | **78.01%** |

### Key findings

**Hash identification is highly accurate** for common digest sizes. The 75.2% on the Kaggle hash dataset reflects a known dataset ambiguity: SHA3-256, BLAKE2b, and GOST all produce 64-char hex digests that are structurally identical to SHA-256. When these are excluded, accuracy exceeds 98%.

**Classical cipher identification** achieves 78% overall, with Caesar at 89% recall. The primary failure mode for single-byte XOR is the 64-char hex collision with SHA-256: short XOR ciphertexts of exactly 32 bytes are indistinguishable from MD5 digests (32-char hex) and SHA-256 (64-char hex) without decryption.

**Modern cipher heuristics** are limited by the Kaggle dataset's fixed 11-byte ciphertexts (22 hex chars), which are too short for reliable block-size fingerprinting and are near-identical across AES, RC4, ChaCha20, ECC, and ElGamal. This is a fundamental limitation of pure structural analysis and motivates the LLM-assisted module.

**Known fundamental ambiguity:** Any 32-char hex string can be either an MD5 digest or a DES/Blowfish ciphertext; any 64-char hex string can be either SHA-256 or short XOR/AES ciphertext. Heuristics cannot resolve this without additional context — this is where LLM analysis adds value.

---

## Cryptanalysis Module

See `base_decryption/base_decryption.py` and `test_baseline.py` for Caesar and single-byte XOR decryption using word-list scoring.

---

## Setup

```bash
# No external dependencies required for baseline and cryptanalysis modules
python3 --version   # Python 3.10+ recommended

# Regenerate datasets
python3 data/generate_hash_dataset.py
python3 -c "from base_decryption.cipher_dataset_generator import create_cipher_dataset; create_cipher_dataset()"

# Run cryptanalysis tests
python3 test_baseline.py

# Run artifact identifier evaluation (requires data/dataset.csv from Kaggle)
python3 baseline/evaluate_identifier.py
```

---

## License

Academic use. Datasets used under their respective licenses:
- SecLists: MIT
- Kaggle Cryptographic Algorithm Classification Dataset: CC BY-SA 4.0
- neoneye/base64-decode-v2: MIT
