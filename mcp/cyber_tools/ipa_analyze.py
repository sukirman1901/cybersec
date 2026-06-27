import zipfile
import plistlib
import os


async def ipa_analyze(path: str) -> dict:
    """Analyze iOS IPA file — metadata, entitlements, plist, permissions."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            names = z.namelist()
            plist_paths = [n for n in names if n.endswith('Info.plist')]
            entitlements = {}
            if plist_paths:
                with z.open(plist_paths[0]) as f:
                    plist = plistlib.load(f)
                entitlements = {
                    k: v for k, v in plist.items()
                    if any(s in k.lower() for s in ['entitlement', 'keychain', 'icloud', 'push', 'aps'])
                }
            suspicious = [
                n for n in names
                if any(x in n.lower() for x in ['dylib', 'framework', '.sh'])
            ]
            return {
                "path": path,
                "app_name": os.path.basename(path),
                "file_count": len(names),
                "plist_found": bool(plist_paths),
                "entitlements": entitlements,
                "suspicious_files_count": len(suspicious),
                "suspicious_files": suspicious[:20],
            }
    except Exception as e:
        return {"path": path, "error": str(e)}
