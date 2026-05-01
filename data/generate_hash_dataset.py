"""
generate_hash_dataset.py
========================
Generates data/hash_dataset.csv — a balanced dataset of MD5, SHA-1, and
SHA-256 digests computed from sentences in base_decryption/sentences.txt
(sourced from the SecLists repository).

Usage
-----
    python3 data/generate_hash_dataset.py

Output columns
--------------
    Algorithm : "MD5" | "SHA-1" | "SHA-256"
    Hash      : hex digest string
    Plaintext : source sentence (for reference; not used during evaluation)
"""

import csv
import hashlib
import os
import random
from pathlib import Path

ROOT       = Path(__file__).resolve().parent.parent
SENTENCES  = ROOT / "base_decryption" / "sentences.txt"
OUTPUT     = ROOT / "data" / "hash_dataset.csv"
SAMPLES_PER_ALGO = 500
RANDOM_SEED      = 42


def main():
    with open(SENTENCES, encoding="utf-8", errors="ignore") as f:
        sentences = [line.strip() for line in f if line.strip()]

    if len(sentences) < SAMPLES_PER_ALGO:
        raise ValueError(
            f"Need at least {SAMPLES_PER_ALGO} sentences, found {len(sentences)}."
        )

    random.seed(RANDOM_SEED)
    sample = random.sample(sentences, SAMPLES_PER_ALGO)

    HASH_FUNCS = {
        "MD5":     hashlib.md5,
        "SHA-1":   hashlib.sha1,
        "SHA-256": hashlib.sha256,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for text in sample:
        for algo, fn in HASH_FUNCS.items():
            digest = fn(text.encode()).hexdigest()
            rows.append({"Algorithm": algo, "Hash": digest, "Plaintext": text})

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Algorithm", "Hash", "Plaintext"])
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    print(f"Generated {total} hash samples ({SAMPLES_PER_ALGO} per algorithm) → {OUTPUT}")


if __name__ == "__main__":
    main()
