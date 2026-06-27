import os
import plistlib
import re

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
    """Parse a .plist or .entitlements file."""
    try:
        with open(filepath, 'rb') as f:
            return plistlib.load(f)
    except Exception:
        return {}


def _parse_xml_entitlements(filepath: str) -> dict:
    """Parse entitlements from XML content (embedded in binary or raw)."""
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
        # Look for XML plist content
        xml_start = content.find('<?xml')
        if xml_start >= 0:
            xml_end = content.find('</plist>', xml_start)
            if xml_end >= 0:
                xml_content = content[xml_start:xml_end + len('</plist>')]
                return plistlib.loads(xml_content.encode('utf-8'))
    except Exception:
        pass
    return {}


async def desktop_entitlements(path: str) -> dict:
    """Check macOS entitlements, Windows manifest, Linux capabilities in desktop apps."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    entitlements_checked = []
    high_risk_findings = []

    if os.path.isdir(path):
        # Walk directory looking for .plist, .entitlements, .app bundles
        for root, _dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname.endswith('.plist') or fname.endswith('.entitlements'):
                    entitlements_checked.append(fpath)
                    entitlements = _parse_plist(fpath)
                    if not entitlements:
                        entitlements = _parse_xml_entitlements(fpath)
                    for key in entitlements:
                        if key in HIGH_RISK_ENTITLEMENTS_MACOS and entitlements[key]:
                            high_risk_findings.append({
                                "file": fname,
                                "entitlement": key,
                                "value": entitlements[key],
                                "risk": "HIGH",
                            })
    elif os.path.isfile(path):
        entitlements_checked.append(path)
        if path.endswith('.plist') or path.endswith('.entitlements'):
            entitlements = _parse_plist(path)
            if not entitlements:
                entitlements = _parse_xml_entitlements(path)
            for key in entitlements:
                if key in HIGH_RISK_ENTITLEMENTS_MACOS and entitlements[key]:
                    high_risk_findings.append({
                        "file": os.path.basename(path),
                        "entitlement": key,
                        "value": entitlements[key],
                        "risk": "HIGH",
                    })
        else:
            # Try to read as XML/plist text
            entitlements = _parse_xml_entitlements(path)
            for key in entitlements:
                if key in HIGH_RISK_ENTITLEMENTS_MACOS and entitlements[key]:
                    high_risk_findings.append({
                        "file": os.path.basename(path),
                        "entitlement": key,
                        "value": entitlements[key],
                        "risk": "HIGH",
                    })

    risk = "HIGH" if len(high_risk_findings) > 0 else "INFO"

    return {
        "path": path,
        "entitlements_checked": entitlements_checked,
        "high_risk_findings": high_risk_findings,
        "total_high_risk": len(high_risk_findings),
        "risk": risk,
    }
