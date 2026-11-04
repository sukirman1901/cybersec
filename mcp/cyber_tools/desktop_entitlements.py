import os
import plistlib
import stat
from xml.parsers.expat import ExpatError

MAX_BYTES = 1024 * 1024
MAX_FILES = 100

# High-risk macOS entitlements
HIGH_RISK_ENTITLEMENTS_MACOS = [
    'com.apple.security.cs.disable-library-validation',
    'com.apple.security.cs.allow-dyld-environment-variables',
    'com.apple.security.cs.allow-jit',
    'com.apple.security.cs.allow-unsigned-executable-memory',
    'com.apple.security.cs.debugger',
    'com.apple.security.device.audio-input',
    'com.apple.security.device.camera',
    'com.apple.security.device.usb',
    'com.apple.security.personal-information.addressbook',
    'com.apple.security.personal-information.location',
    'com.apple.security.personal-information.photos',
    'com.apple.security.network.client',
    'com.apple.security.network.server',
    'com.apple.security.files.user-selected.read-write',
    'com.apple.security.files.downloads.read-write',
]


def _parse_plist(filepath: str) -> dict:
    """Read at most 1 MiB; parsing failures must not be reported as clean."""
    info = os.lstat(filepath)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
        raise ValueError('Unsupported or oversized file')
    def open_regular(name, flags):
        return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with open(filepath, 'rb', opener=open_regular) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise OSError('File changed before open')
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Oversized file')
    if not data.startswith(b'bplist'):
        start = data.find(b'<?xml')
        if start < 0:
            start = data.find(b'<plist')
        end = data.find(b'</plist>', max(start, 0))
        if start >= 0 and end >= 0:
            data = data[start:end + len(b'</plist>')]
    result = plistlib.loads(data)
    if not isinstance(result, dict):
        raise ValueError('Entitlements must be a dictionary')
    return result


def _parse_xml_entitlements(filepath: str) -> dict:
    return _parse_plist(filepath)


async def desktop_entitlements(path: str) -> dict:
    """Inspect local plist declarations, not effective code-signing entitlements."""
    if not isinstance(path, str) or not os.path.exists(path) or os.path.islink(path):
        return {"error": "Expected an existing artifact, not a symlink", "coverage_complete": False, "execution_status": "not_started"}
    entitlements_checked = []
    high_risk_findings = []
    errors = []
    candidates = []
    if os.path.isdir(path):
        entries = 0
        for root, dirs, files in os.walk(path, onerror=lambda _: errors.append("Directory unreadable")):
            entries += len(dirs) + len(files)
            if entries > 1000:
                errors.append("Directory entry budget exceeded")
                break
            if any(os.path.islink(os.path.join(root, d)) for d in dirs):
                errors.append("Symlink directory skipped")
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for fname in files:
                if fname.endswith(('.plist', '.entitlements')):
                    candidates.append(os.path.join(root, fname))
    else:
        candidates = [path]
    if len(candidates) > MAX_FILES:
        errors.append("100-file analysis limit exceeded")
    for index, candidate in enumerate(candidates[:MAX_FILES]):
        try:
            entitlements = _parse_plist(candidate)
            entitlements_checked.append(candidate)
            for key in HIGH_RISK_ENTITLEMENTS_MACOS:
                if key not in entitlements:
                    continue
                if type(entitlements[key]) is not bool:
                    errors.append(f"File {index}: non-boolean entitlement value")
                elif entitlements[key]:
                    high_risk_findings.append({"file": f"artifact-{index}", "entitlement": key,
                                               "value": True, "risk": "MEDIUM", "assessment": "observation",
                                               "confidence": "high", "coverage": "Declared capability only; effective signature and runtime use not verified"})
        except (OSError, ValueError, TypeError, OverflowError, RecursionError, plistlib.InvalidFileException, ExpatError):
            errors.append(f"File {index}: unreadable, oversized or malformed plist")
    risk = "MEDIUM" if high_risk_findings else "UNKNOWN" if errors or not entitlements_checked else "INFO"
    complete = not errors and bool(entitlements_checked)
    return {
        "path": path,
        "entitlements_checked": entitlements_checked,
        "high_risk_findings": high_risk_findings,
        "total_high_risk": len(high_risk_findings),
        "risk": risk,
        "errors": errors,
        "coverage_complete": complete,
        "execution_status": "completed" if complete else "partial" if entitlements_checked else "not_started",
        "coverage": "Local plist declarations only, including embedded XML/binary plist; 1 MiB/file, 100 files, 1000 directory entries. macOS signatures, Windows manifests and Linux capabilities not validated.",
    }
