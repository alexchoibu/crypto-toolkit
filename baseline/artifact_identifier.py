"""
Baseline Artifact Identifier
Detects and classifies cryptographic artifacts using structural heuristics
and information-theoretic features (no keys, no decryption attempted here).


Supported artifact categories
──────────────────────────────
Hash        : MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
Encoding    : Base64, Base64-URL, Base32, Hex (readable plaintext)
Cipher/hex  : AES, DES (8-byte block), RC4 (stream cipher)
              (heuristic based on block-byte alignment and entropy)
Cipher/b64  : RSA (long Base64, high byte entropy)
Classical   : Caesar, SingleByteXOR
"""

import re
import base64
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IdentificationResult:
    artifact_type: str    # "hash" | "encoding" | "cipher" | "unknown"
    algorithm:     str    # e.g. "MD5", "Base64", "AES", "Caesar"
    confidence:    float  # 0.0 – 1.0
    notes:         str    = field(default="")


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _char_entropy(s: str) -> float:
    """Shannon entropy over characters (bits/char)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _byte_entropy(b: bytes) -> float:
    """Shannon entropy over raw bytes (bits/byte)."""
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_HEX_RE         = re.compile(r'^[0-9a-fA-F]+$')
_HEX_EVEN_RE    = re.compile(r'^(?:[0-9a-fA-F]{2})+$')
_BASE64_RE      = re.compile(r'^[A-Za-z0-9+/]+=*$')
_BASE64_URL_RE  = re.compile(r'^[A-Za-z0-9_\-]+=*$')
_BASE32_RE      = re.compile(r'^[A-Z2-7]+=*$')
_ALPHA_PUNCT_RE = re.compile(r'^[A-Za-z\s.,!?\'"()\-:;]+$')


# ─────────────────────────────────────────────────────────────────────────────
# Hash detection
# ─────────────────────────────────────────────────────────────────────────────

# (algorithm_name, hex_output_length, minimum_hex_char_entropy)
# Entropy threshold separates genuine hashes from XOR ciphertexts that happen
# to be the same length (XOR of English text yields a skewed byte distribution).
HASH_PROFILES: list[tuple[str, int, float]] = [
    ("MD5",      32, 3.30),
    ("SHA-1",    40, 3.30),
    ("SHA-224",  56, 3.40),
    ("SHA-256",  64, 3.40),
    ("SHA-384",  96, 3.50),
    ("SHA-512", 128, 3.50),
]

HASH_LENGTHS: frozenset[int] = frozenset(ln for _, ln, _ in HASH_PROFILES)


def detect_hash(artifact: str) -> Optional[IdentificationResult]:
    """Identify cryptographic hash digests by hex length + entropy."""
    s = artifact.strip()
    if not _HEX_RE.match(s):
        return None
    length = len(s)
    for name, expected, min_ent in HASH_PROFILES:
        if length == expected:
            ent = _char_entropy(s.lower())
            if ent < min_ent:
                return None   # low entropy → likely XOR / structured data
            conf = 0.95 if ent >= 3.60 else 0.75
            return IdentificationResult(
                "hash", name, conf,
                f"length={length}, hex_entropy={ent:.3f}"
            )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Hex-ciphertext detection   
# ─────────────────────────────────────────────────────────────────────────────

def detect_hex_cipher(artifact: str) -> Optional[IdentificationResult]:
    """
    Detect modern symmetric ciphers whose output is stored as raw hex.

    Criteria
    --------
    - Even-length hex, NOT at a known hash length
    - Decoded bytes: byte entropy > 3.8 bits/byte  (near-random)
    - Decoded bytes: < 60 % printable ASCII         (not readable text)

    Algorithm guess from decoded byte count
    ----------------------------------------
    n % 16 == 0, n >= 16  →  AES (16-byte block) or Camellia/Serpent
    n %  8 == 0, n >= 8   →  DES - like
    otherwise              →  RC4 / ChaCha20 / stream cipher
    """
    s = artifact.strip()
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not _HEX_EVEN_RE.match(s):
        return None
    if len(s) in HASH_LENGTHS:
        return None

    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None

    printable = sum(32 <= b < 127 for b in raw) / len(raw)
    if printable > 0.65:
        return None   # probably hex-encoded plaintext

    ent = _byte_entropy(raw)
    n   = len(raw)

    # Short ciphertexts (< 20 bytes) have fewer unique byte values so entropy
    # is naturally lower.  We scale the threshold: for n bytes the maximum
    # observable entropy is log2(n), so we require ≥ 60 % of that maximum.
    min_ent = min(3.8, 0.60 * math.log2(max(n, 2)))
    if ent < min_ent:
        return None   # not random enough for ciphertext

    notes = f"decoded_bytes={n}, byte_entropy={ent:.3f}, printable={printable:.2f}"

    if n % 16 == 0 and n >= 16:
        return IdentificationResult("cipher", "AES", 0.65, notes)
    elif n % 8 == 0 and n >= 8:
        return IdentificationResult("cipher", "DES", 0.55, notes)
    else:
        return IdentificationResult("cipher", "RC4", 0.45, notes)


# ─────────────────────────────────────────────────────────────────────────────
# RSA detection  (long Base64)
# ─────────────────────────────────────────────────────────────────────────────

def detect_rsa(artifact: str) -> Optional[IdentificationResult]:
    """
    RSA ciphertexts are long Base64 strings (≥ 300 chars).
    Decoded bytes have near-maximum entropy (> 7.5 bits/byte).
    """
    s = artifact.strip()
    if len(s) < 300:
        return None
    if not (_BASE64_RE.match(s) or _BASE64_URL_RE.match(s)):
        return None
    try:
        decoded = base64.b64decode(s + "==")
    except Exception:
        return None
    if len(decoded) < 200:
        return None
    ent = _byte_entropy(decoded)
    if ent > 7.0:
        return IdentificationResult(
            "cipher", "RSA", 0.80,
            f"b64_len={len(s)}, decoded_bytes={len(decoded)}, byte_entropy={ent:.3f}"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Encoding detection
# ─────────────────────────────────────────────────────────────────────────────

_WORD_RE = re.compile(r'[a-zA-Z]{3,}')


def _text_readability(raw: bytes) -> float:
    """Fraction of characters that belong to 3+ char alphabetic runs.
    Readable English scores > 0.40; XOR-encrypted text < 0.20."""
    try:
        decoded = raw.decode("ascii", errors="replace")
    except Exception:
        return 0.0
    if not decoded:
        return 0.0
    words = _WORD_RE.findall(decoded)
    return sum(len(w) for w in words) / len(decoded)


def detect_hex_encoding(artifact: str) -> Optional[IdentificationResult]:
    """
    Hex-encoded readable text: decoded bytes are mostly printable ASCII
    AND the content contains recognisable alphabetic runs.

    The readability gate prevents XOR-of-English ciphertexts from being
    mis-identified here: XOR output is often >80% printable but the decoded
    bytes are garbled (low alphabetic-word ratio).
    """
    s = artifact.strip()
    if len(s) < 4 or len(s) % 2 != 0:
        return None
    if not _HEX_EVEN_RE.match(s):
        return None
    if len(s) in HASH_LENGTHS:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None

    printable = sum(32 <= b < 127 for b in raw) / len(raw)
    if printable < 0.55:
        return None

    readability = _text_readability(raw)
    if printable > 0.80 and readability > 0.35:
        preview = raw[:40].decode("ascii", errors="replace")
        return IdentificationResult(
            "encoding", "Hex", 0.85,
            f"printable={printable:.2f}, readability={readability:.2f}, preview='{preview}'"
        )
    return None


def detect_base64(artifact: str) -> Optional[IdentificationResult]:
    """
    Standard or URL-safe Base64.
    - Excludes pure-hex strings at known hash lengths.
    - Excludes very long strings (≥ 300 chars) — handled by detect_rsa.
    - If decoded bytes have very high entropy, re-classifies as AES cipher.
    """
    s = artifact.strip()
    if len(s) < 4 or len(s) >= 300:
        return None
    if _HEX_RE.match(s) and len(s) in HASH_LENGTHS:
        return None

    is_std = bool(_BASE64_RE.match(s)) and len(s) % 4 == 0
    is_url = bool(_BASE64_URL_RE.match(s)) and len(s) % 4 == 0
    if not (is_std or is_url):
        return None

    # Pure hex strings accidentally satisfy the Base64 charset (0-9, a-f are all
    # valid Base64 characters). Exclude them — hash / XOR / hex-cipher detectors
    # handle pure hex.
    if _HEX_RE.match(s):
        return None

    try:
        decoded = base64.b64decode(s + "==")
    except Exception:
        return None
    if len(decoded) == 0:
        return None

    byte_ent = _byte_entropy(decoded)
    # High decoded-byte entropy + block-aligned → likely AES-CBC in Base64
    if byte_ent > 7.5 and len(decoded) >= 16 and len(decoded) % 16 == 0:
        return IdentificationResult(
            "cipher", "AES", 0.60,
            f"b64_decoded={len(decoded)}, byte_entropy={byte_ent:.3f}"
        )

    variant = "Base64-URL" if (is_url and not is_std) else "Base64"
    char_ent = _char_entropy(s)
    conf = 0.90 if char_ent > 4.5 else 0.78
    return IdentificationResult(
        "encoding", variant, conf,
        f"decoded_bytes={len(decoded)}, char_entropy={char_ent:.3f}"
    )


def detect_base32(artifact: str) -> Optional[IdentificationResult]:
    """Base32 encoded data: restricted charset [A-Z2-7=], valid decode."""
    s = artifact.strip().upper()
    if len(s) < 8 or not _BASE32_RE.match(s):
        return None
    try:
        decoded = base64.b32decode(s)
        if len(decoded) == 0:
            return None
        return IdentificationResult(
            "encoding", "Base32", 0.88,
            f"decoded_bytes={len(decoded)}"
        )
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Classical cipher detection
# ─────────────────────────────────────────────────────────────────────────────

_ENGLISH_COMMON = frozenset(
    "the a an is are was to of and in it he she we you they i my his her "
    "our their this that be have do said with on for at by from".split()
)


def detect_caesar(artifact: str) -> Optional[IdentificationResult]:
    """
    Caesar-shifted text:
      - Only letters, spaces, and common punctuation
      - Letter entropy in [3.5, 4.8]  (shift preserves frequency distribution)
      - Few recognisable English words  (if already plaintext, score would be high)
    """
    s = artifact.strip()
    if len(s) < 6 or not _ALPHA_PUNCT_RE.match(s):
        return None
    letters = s.replace(" ", "").lower()
    ent = _char_entropy(letters)
    if not (3.5 <= ent <= 4.8):
        return None
    words = s.lower().split()
    eng_hits = sum(1 for w in words if w.strip(".,!?;:'\"") in _ENGLISH_COMMON)
    eng_ratio = eng_hits / len(words) if words else 0
    if eng_ratio < 0.15:
        return IdentificationResult(
            "cipher", "Caesar", 0.70,
            f"letter_entropy={ent:.3f}, english_ratio={eng_ratio:.2f}"
        )
    return None


def detect_single_byte_xor(artifact: str) -> Optional[IdentificationResult]:
    """
    Single-byte XOR ciphertext stored as hex:
      - Even-length hex, NOT at a known hash length
      - High byte entropy (> 3.5 bits/byte)
      - Low printable ratio (< 0.65) — encrypted bytes are not readable ASCII

    Note: A 64-hex-char XOR ciphertext overlaps with SHA-256 in length.
    The entropy threshold in detect_hash (≥ 3.4) resolves most cases:
    XOR of English text with a single key typically has hex entropy < 3.4
    because the byte distribution is skewed (one key byte maps to one cluster).
    """
    s = artifact.strip()
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not _HEX_EVEN_RE.match(s):
        return None
    if len(s) in HASH_LENGTHS:
        return None

    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None

    printable = sum(32 <= b < 127 for b in raw) / len(raw)
    ent = _byte_entropy(raw)
    # Require high entropy (ciphertext is near-random) and NOT trivially readable.
    # The readability gate in detect_hex_encoding handles the "printable but garbled"
    # case, so we accept up to 0.95 printable here as long as entropy is high.
    if ent > 3.5 and printable < 0.95:
        return IdentificationResult(
            "cipher", "SingleByteXOR", 0.75,
            f"byte_entropy={ent:.3f}, printable={printable:.2f}"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main identifier
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactIdentifier:
    """
    Runs detectors in priority order and returns the highest-confidence result.
    Stops early when confidence ≥ 0.88 (avoids unnecessary computation).

    Detection order
    ───────────────
    1. RSA            long Base64, very specific
    2. Hash           exact hex length + entropy gate
    3. Base32         very restricted charset
    4. Caesar         alpha-only text, low English-word score
    5. Hex encoding   high printable ratio in decoded bytes
    6. SingleByteXOR  hex, high byte entropy, low printable
    7. Hex cipher     block-aligned high-entropy hex (AES / DES / RC4)
    8. Base64         fallback; also catches AES-in-Base64
    9. Unknown
    """

    _DETECTORS = [
        detect_rsa,
        detect_hash,
        detect_base32,
        detect_caesar,
        detect_hex_encoding,
        detect_single_byte_xor,
        detect_hex_cipher,
        detect_base64,
    ]

    def identify(self, artifact: str) -> IdentificationResult:
        artifact = artifact.strip()
        if not artifact:
            return IdentificationResult("unknown", "Unknown", 0.0, "empty input")

        best: Optional[IdentificationResult] = None
        for detector in self._DETECTORS:
            result = detector(artifact)
            if result is None:
                continue
            if best is None or result.confidence > best.confidence:
                best = result
            if best.confidence >= 0.88:
                break

        if best is None:
            best = IdentificationResult(
                "unknown", "Unknown", 0.0,
                f"char_entropy={_char_entropy(artifact):.3f}"
            )
        return best

    def identify_batch(self, artifacts: list[str]) -> list[IdentificationResult]:
        return [self.identify(a) for a in artifacts]
