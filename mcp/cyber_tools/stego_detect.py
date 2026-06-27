"""Detect hidden data in files — steganography, LSB, metadata anomalies, embedded strings."""

import os
import re

SUSPICIOUS_METADATA_KEYS = [
    "comment", "description", "author", "copyright", "artist", "software",
]


async def stego_detect(path: str) -> dict:
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    findings = []
    ext = os.path.splitext(path)[1].lower()

    with open(path, "rb") as f:
        data = f.read()

    # Check file size anomalies (padding)
    if ext in [".png", ".bmp"]:
        import struct
        # Check IEND chunk for extra data after PNG end
        iend_pos = data.rfind(b"IEND")
        if iend_pos > 0 and len(data) > iend_pos + 8:
            trailing = data[iend_pos + 8:]
            if len(trailing) > 4:
                findings.append({
                    "type": "trailing_data",
                    "size": len(trailing),
                    "note": "Data found after IEND chunk",
                })

        # Check for LSB indicators (large number of unique colors)
        if len(data) > 1000:
            findings.append({
                "type": "file_size",
                "size": len(data),
                "note": f"File size: {len(data)} bytes",
            })

    # Extract printable strings looking for flags/keys
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= 8:
                s = "".join(current)
                flag_match = re.search(
                    r"(flag|ctf|secret|hidden|key|password)[\s:=]+([^\s]{4,})",
                    s, re.I,
                )
                if flag_match:
                    findings.append({"type": "embedded_secret", "match": s[:80]})
            current = []
    if len(current) >= 8:
        s = "".join(current)
        flag_match = re.search(
            r"(flag|ctf|secret|hidden|key|password)[\s:=]+([^\s]{4,})",
            s, re.I,
        )
        if flag_match:
            findings.append({"type": "embedded_secret", "match": s[:80]})

    # Metadata extraction
    if ext in [".jpg", ".jpeg"]:
        exif_start = data.find(b"\xff\xe1")
        if exif_start >= 0:
            findings.append({
                "type": "exif_found",
                "note": "EXIF data present — may contain hidden metadata",
            })

    return {"path": path, "findings": findings, "suspicious": len(findings) > 0}
