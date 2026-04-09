import string
from pathlib import Path


class BaseDecryption:
    def __init__(
        self
    ):
        base_dir = Path(__file__).resolve().parent

        wordlist_path = base_dir / "wordlist.txt"
        common_words_path = base_dir / "1-1000.txt"

        self.word_scores = {}

        # Assign 5 as the score for 1000 common words
        with open(common_words_path, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    self.word_scores[word] = 10

        # Assign 1 as the score for all other words
        with open(wordlist_path, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip().lower()
                if word and word not in self.word_scores:
                    self.word_scores[word] = 1

    # Function to score decrypted text based on recognized words
    # and their scores
    def score_decryption(self, decrypted_text: str) -> int:

        # If the decrypted text has a low ratio of printable characters,
        # it's likely not valid, return a very low score to filter it out
        printable = sum(c in string.printable for c in decrypted_text)
        printable_ratio = printable / len(decrypted_text)

        if printable_ratio < 0.85:
            return -1000

        score = 0
        decrypted_words = decrypted_text.split()
        recognized_words = 0

        # Score each recognized word based on the predefined scores
        for word in decrypted_words:
            word = word.lower()
            if word in self.word_scores:
                recognized_words += 1
                score += self.word_scores[word]

        # Add a bonus score based on the percentage of recognized words
        if decrypted_words:
            score += (recognized_words / len(decrypted_words)) * 10

        return score

    # Single-byte XOR decryption method that tries all possible keys (0-255)
    # and scores the decrypted text to find the best key
    def single_byte_xor(self, encrypted_text: str) -> tuple:
        best_score = float("-inf")
        best_key = None
        best_plaintext = ""

        try:
            cipher_bytes = bytes.fromhex(encrypted_text)
        except ValueError:
            return float("-inf"), "", None

        for key in range(256):
            decrypted_bytes = bytes(b ^ key for b in cipher_bytes)

            try:
                decrypted_text = decrypted_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue

            score = self.score_decryption(decrypted_text)

            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = decrypted_text

        return best_score, best_plaintext, best_key

    # Caesar cipher decryption method that tries all possible shifts (1-25)
    # and scores the decrypted text to find the best shift
    def caesar_cipher(self, encrypted_text: str) -> tuple:
        best_score = float("-inf")
        best_key = None
        best_plaintext = ""
        for key in range(1, 26):
            decrypted_text = ""
            for char in encrypted_text:
                if char in string.ascii_letters:
                    if char.islower():
                        decrypted_char = chr(
                            (ord(char) - ord("a") - key) % 26 + ord("a")
                        )
                    else:
                        decrypted_char = chr(
                            (ord(char) - ord("A") - key) % 26 + ord("A")
                        )
                else:
                    decrypted_char = char
                decrypted_text += decrypted_char

            score = self.score_decryption(decrypted_text)

            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = decrypted_text

        return best_score, best_plaintext, best_key

    # Main decryption function that tries all decryption methods
    # compares their scores to guess the most likely method and key
    def decrypt(self, encrypted_text: str) -> str:

        caesar_cipher_score, c_plain_text, caesar_key = self.caesar_cipher(
            encrypted_text
        )

        single_byte_xor_score, xor_plain_text, xor_key = self.single_byte_xor(
            encrypted_text
        )

        # Compare the scores of both decryption methods
        # return the one with the higher score as the guessed method
        if caesar_cipher_score > single_byte_xor_score:
            return "caesar", c_plain_text, caesar_key
        else:
            return "single_byte_xor", xor_plain_text, xor_key
