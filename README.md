# Automated Cryptanalysis and Cryptographic Algorithm Identification Toolkit

Automating the identification of cryptographic artifacts can improve efficiency and reduce reliance on manual analysis. This project proposes the development of an automated toolkit capable of identifying common cryptographic artifacts, including classical ciphers, XOR-based encryption, encoding schemes, and hash outputs, while performing automated cryptanalysis where feasible. The project will also evaluate whether LLM-assisted analysis can improve performance compared to traditional heuristic and statistical approaches.

```
crypto-toolkit-main/
│
├── README.md
├── .gitignore
├── evaluation.py                    ← Evaluation & comparison script
├── test_baseline.py                 ← Baseline test script
│
├── baseline/                        ← Rule-based artifact identifier
│   ├── __init__.py
│   ├── artifact_identifier.py       ← ArtifactIdentifier class - main detector
│   └── evaluate_identifier.py       ← Evaluation against all three datasets
│
├── base_decryption/
│   ├── __init__.py
│   ├── base_decryption.py           ← Main decryption class (Caesar + XOR)
│   ├── cipher_dataset_generator.py  ← Dataset generator (change INPUT_FILE to swap datasets)
│   ├── sentences.txt                ← Simple English sentences (Kaggle)
│   ├── harder_sentences.txt         ← High-quality sentences with proper nouns (HuggingFace)
│   ├── wordlist.txt                 ← ~300k English words for scoring
│   └── 1-1000.txt                   ← Top 1000 common words (weighted higher)
│
├── data/
|   |── 0_9999_hashes.csv                   ← Generated umber list hash data
|   |── 4-digits-0000-9999.txt              ← Number list containing strings 0000 to 9999
│   |── cipher_dataset.csv                  ← Generated dataset (10k Caesar + XOR samples)
|   |── create_data.py                      ← Dataset generation/accumulation script
|   |── cryptography_dataset_enhanced.csv   ← First complex algorithm dataset from Kaggle
|   |── cryptography_dataset_processed.csv  ← Second complex algorithm dataset from Kaggle
|   |── data.csv                            ← Organized encoded dataset
|   |── data.jsonl                          ← Encoded artifacts dataset from Hugging Face
│   |── dataset.csv                         ← Complex algorithm dataset (AES, RSA, etc.)
|   |── hashgen.py                          ← Hash generation script from SecLists
│   ├── evaluation_results.csv              ← Output: row-by-row results from evaluation.py
│   └── evaluation_chart.png                ← Output: visual comparison chart
│
└── llm/
    ├── __init__.py
    ├── llm_simple.py                ← LLM decryption for Caesar + XOR (Llama3.2)
    ├── llm_complex.py               ← LLM identifier for 20+ algorithm types
    ├── test_llm_simple.py           ← Test script for llm_simple
    └── test_llm_complex.py          ← Test script for llm_complex


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

For a quick start:

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

For evaluation run with: `python3 baseline/evaluate_identifier.py` from the repo root.

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
