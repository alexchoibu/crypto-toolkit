import csv
import random
from pathlib import Path
import string

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"

INPUT_FILE = BASE_DIR / "sentences.txt"
OUTPUT_FILE = DATA_DIR / "cipher_dataset.csv"

NUM_ROWS = 10000


def caesar_encrypt(text, shift):
    result = []

    for c in text:
        if c in string.ascii_letters:
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)

    return "".join(result)


def xor_encrypt(text, key):
    text_bytes = text.encode("utf-8")
    encrypted = bytes(c ^ key for c in text_bytes)

    return encrypted.hex()


# Function to generate a dataset of algorithm,
# plaintext, ciphertext, and key for both Caesar and single-byte XOR ciphers
# The dataset is saved as a CSV in data directory
# It produces NUM_ROWS unique samples,
# ensuring no duplicates of (plaintext, algorithm, key) combinations
def create_cipher_dataset():

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        sentences = [line.strip() for line in f if line.strip()]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # Columns
        writer.writerow(["Algorithm", "Input", "Output", "Key"])

        seen = set()

        for _ in range(NUM_ROWS):
            plaintext = random.choice(sentences)
            algorithm = random.choice(["caesar", "single_byte_xor"])
            key = -1
            if algorithm == "caesar":
                key = random.randint(1, 25)
            else:
                key = random.randint(0, 255)

            # plaintext, algorithm and key combination picked
            combo = (plaintext, algorithm, key)

            # If combination is already seen, skip to ensure uniqueness
            if combo in seen:
                continue

            seen.add(combo)

            # Encrypt the plaintext using the chosen algorithm and key
            # And write the row to the CSV file
            if algorithm == "caesar":
                ciphertext = caesar_encrypt(plaintext, key)
            else:
                ciphertext = xor_encrypt(plaintext, key)

            writer.writerow([algorithm, plaintext, ciphertext, key])

    print(f"Generated {NUM_ROWS} rows in {OUTPUT_FILE}")
