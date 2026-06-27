import re

HASH_PATTERNS = [
    (r"^\$2[ayb]\$.{56}", "bcrypt", "BCrypt", 60),
    (r"^\$5\$.{52}", "sha256-crypt", "SHA-256 Crypt", 52),
    (r"^\$6\$.{84}", "sha512-crypt", "SHA-512 Crypt", 84),
    (r"^[a-f0-9]{32}$", "md5", "MD5", 32),
    (r"^[a-f0-9]{40}$", "sha1", "SHA-1", 40),
    (r"^[a-f0-9]{56}$", "sha224", "SHA-224", 56),
    (r"^[a-f0-9]{64}$", "sha256", "SHA-256", 64),
    (r"^[a-f0-9]{96}$", "sha384", "SHA-384", 96),
    (r"^[a-f0-9]{128}$", "sha512", "SHA-512", 128),
    (r"^\$NT\$.{32}", "ntlm", "NTLM", 32 + 4),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "lm-ntlm", "LM:NTLM hash", 65),
    (r"^\$1\$.{34}", "md5-crypt", "MD5 Crypt", 34),
    (r"^[0-9a-f]{16}$", "mysql", "MySQL pre-4.1", 16),
    (r"^\*[0-9a-f]{40}$", "mysql-sha1", "MySQL SHA-1", 41),
    (r"^[0-9a-f]{41}$", "mysql-sha1-alt", "MySQL SHA-1 (alt)", 41),
    (r"^sk-[a-zA-Z0-9]{20,}$", "openai-key", "OpenAI API Key", None),
    (r"^ghp_[a-zA-Z0-9]{36}$", "github-pat", "GitHub Personal Access Token", None),
    (r"^AKIA[0-9A-Z]{16}$", "aws-key", "AWS Access Key ID", 20),
]


async def hash_analyze(hash_string: str) -> dict:
    matches = []
    for pattern, name, display_name, length in HASH_PATTERNS:
        if re.match(pattern, hash_string.strip()):
            matches.append({"type": name, "display_name": display_name, "length": length, "confidence": "high"})

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

    hashcat_modes = {m["type"]: m for m in matches}
    mode_map = {
        "bcrypt": 3200, "sha512-crypt": 1800, "sha256-crypt": 7400,
        "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
        "ntlm": 1000, "md5-crypt": 500,
    }

    return {
        "hash": hash_string[:50] + "..." if len(hash_string) > 50 else hash_string,
        "matches": matches,
        "hashcat_mode": [mode_map.get(m["type"]) for m in matches if m["type"] in mode_map],
        "john_format": [m["type"] for m in matches],
        "crack_command": f"hashcat -m {mode_map.get(matches[0]['type'], 0)} hash.txt wordlist.txt" if matches else "",
    }
