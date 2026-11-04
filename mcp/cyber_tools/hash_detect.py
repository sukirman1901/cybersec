import re
from collections import Counter
from math import log2

HASH_PATTERNS = [
    ("MD5", r'^[a-f0-9]{32}$', 32, "hashcat: 0"),
    ("SHA1", r'^[a-f0-9]{40}$', 40, "hashcat: 100"),
    ("SHA256", r'^[a-f0-9]{64}$', 64, "hashcat: 1400"),
    ("SHA512", r'^[a-f0-9]{128}$', 128, "hashcat: 1700"),
    ("bcrypt", r'^\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$', 60, "hashcat: 3200"),
    ("bcrypt_old", r'^\$2\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$', 60, "hashcat: 3200"),
    ("scrypt", r'^\$7\$\d{2}\$[./A-Za-z0-9]{53}$', None, "hashcat: 8900"),
    ("argon2", r'^\$argon2(?:id|i|d)\$v=(?:16|19)\$m=[1-9]\d*,t=[1-9]\d*,p=[1-9]\d*\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$', None, None),
    ("NTLM", r'^[a-f0-9]{32}$', 32, "hashcat: 1000"),
    ("LM", r'^[a-f0-9]{32}$', 32, "hashcat: 3000"),
    ("MySQL < 4.1", r'^[a-f0-9]{16}$', 16, "hashcat: 200"),
    ("MySQL 5+", r'^\*[a-f0-9]{40}$', 41, "hashcat: 300"),
    ("PostgreSQL", r'^md5[a-f0-9]{32}$', 36, "hashcat: 10"),
    ("SHA256_crypt", r'^\$5\$(?:rounds=[1-9][0-9]{3,8}\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$', None, "hashcat: 7400"),
    ("SHA512_crypt", r'^\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$', None, "hashcat: 1800"),
    ("SHA3-256", r'^[a-f0-9]{64}$', 64, "hashcat: 17400"),
    ("RIPEMD160", r'^[a-f0-9]{40}$', 40, "hashcat: 6000"),
    ("CRC32", r'^[a-f0-9]{8}$', 8, "hashcat: 11500"),
    ("DES_UNIX", r'^[./A-Za-z0-9]{13}$', 13, "hashcat: 1500"),
    ("MD5_APR", r'^\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$', None, "hashcat: 1600"),
]

async def hash_detect(hash_string: str) -> dict:
    if not isinstance(hash_string, str) or len(hash_string) > 4096:
        return {'error':'Expected a string of at most 4096 characters', 'hash':'[REDACTED]',
                'coverage':'Input validation only', 'count':0, 'possible_types':[]}
    matches = []
    h = hash_string.strip()

    for name, pattern, length, hashcat_id in HASH_PATTERNS:
        if re.fullmatch(pattern, h, re.I):
            match_info = {"type": name, "hashcat_mode": hashcat_id,
                          "confidence":"MEDIUM", "coverage":"Format heuristic only; algorithm and tool mode not validated"}
            # Disambiguate: MD5 vs NTLM vs LM (all 32 hex chars)
            if name == "MD5":
                if h.startswith("0x"):
                    continue  # skip, will be caught by NTLM or other
                # Could be MD5, NTLM, or LM
                match_info["note"] = "Could also be NTLM (hashcat 1000) or LM (hashcat 3000) — check context"
            if name in ["SHA1", "RIPEMD160"]:
                match_info["note"] = f"Could also be SHA1 or RIPEMD160 — both are 40 hex chars"
            matches.append(match_info)

    # Additional entropy analysis
    entropy = 0
    if h:
        for count in Counter(h).values():
            p = count / len(h)
            if p > 0:
                entropy -= p * log2(p)

    return {
        "hash": "[REDACTED]",
        "length": len(h),
        "entropy": round(entropy, 2),
        "entropy_assessment": "Observed character Shannon entropy, not cryptographic strength or source randomness",
        "coverage": "Offline format candidates only; hash identity and credential validity untested",
        "possible_types": matches if matches else [{"type": "unknown", "note": "Hash format not recognized"}],
        "count": len(matches),
    }
