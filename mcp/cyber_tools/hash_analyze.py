"""Offline format recognition, limited to 4,096 input characters.

Recognized formats are ASCII (4 KiB at the limit). A character cap also bounds
malformed Unicode input before stripping or regex matching, without encoding it.
"""

import re

MAX_HASH_CHARS = 4 * 1024

HASH_PATTERNS = [
    (r"\$2[ayb]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}", "bcrypt", "BCrypt", 60),
    (r"\$5\$(?:rounds=[1-9][0-9]{3,8}\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}", "sha256-crypt", "SHA-256 Crypt", None),
    (r"\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}", "sha512-crypt", "SHA-512 Crypt", None),
    (r"^[a-f0-9]{32}$", "md5", "MD5", 32),
    (r"^[a-f0-9]{40}$", "sha1", "SHA-1", 40),
    (r"^[a-f0-9]{56}$", "sha224", "SHA-224", 56),
    (r"^[a-f0-9]{64}$", "sha256", "SHA-256", 64),
    (r"^[a-f0-9]{96}$", "sha384", "SHA-384", 96),
    (r"^[a-f0-9]{128}$", "sha512", "SHA-512", 128),
    (r"\$NT\$[a-fA-F0-9]{32}", "ntlm", "NTLM", 32 + 4),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "lm-ntlm", "LM:NTLM hash", 65),
    (r"\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}", "md5-crypt", "MD5 Crypt", None),
    (r"^[0-9a-f]{16}$", "mysql", "MySQL pre-4.1", 16),
    (r"^\*[0-9a-f]{40}$", "mysql-sha1", "MySQL SHA-1", 41),
    (r"^sk-[a-zA-Z0-9]{20,}$", "openai-key", "OpenAI API Key", None),
    (r"^ghp_[a-zA-Z0-9]{36}$", "github-pat", "GitHub Personal Access Token", None),
    (r"^AKIA[0-9A-Z]{16}$", "aws-key", "AWS Access Key ID", 20),
]


async def hash_analyze(hash_string: str) -> dict:
    if not isinstance(hash_string, str):
        return {"error": "Hash must be a string"}
    if len(hash_string) > MAX_HASH_CHARS:
        return {"error": "Hash exceeds 4096-character analysis limit",
                "error_code": "input_too_large", "max_characters": MAX_HASH_CHARS}
    h = hash_string.strip()
    matches = []
    for pattern, name, display_name, length in HASH_PATTERNS:
        # Hex casing is insignificant; credential prefixes remain case-sensitive.
        flags = re.IGNORECASE if name in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "lm-ntlm", "mysql", "mysql-sha1"} else 0
        if re.fullmatch(pattern, h, flags):
            matches.append({"type": name, "display_name": display_name, "length": len(h), "confidence": "medium"})
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        matches.extend({"type": name, "display_name": name.upper(), "length": 32, "confidence": "medium"}
                       for name in ("ntlm", "lm"))

    if not matches:
        h = hash_string.strip()
        length_guesses = {
            32: "MD5, NTLM, LM",
            40: "SHA-1, MySQL SHA-1",
            56: "SHA-224",
            64: "SHA-256",
            96: "SHA-384",
            128: "SHA-512",
        }
        guess = length_guesses.get(len(h), "Unknown")
        matches.append({"type": "unknown", "display_name": f"Possible: {guess}", "length": len(h), "confidence": "low"})

    mode_map = {
        "bcrypt": 3200, "sha512-crypt": 1800, "sha256-crypt": 7400,
        "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
        "ntlm": 1000, "md5-crypt": 500,
    }

    return {
        "hash": "[REDACTED]",
        "matches": matches,
        "hashcat_mode": [mode_map.get(m["type"]) for m in matches if m["type"] in mode_map],
        "john_format": [m["type"] for m in matches],
        "crack_command": f"hashcat -m {mode_map[matches[0]['type']]} hash.txt wordlist.txt" if len(matches) == 1 and matches[0]["type"] in mode_map and h.startswith("$") else "",
        "coverage": "Offline format heuristics only; candidates are not algorithm identification or credential validation. Hashcat modes are candidate mappings, not verified recommendations.",
    }
