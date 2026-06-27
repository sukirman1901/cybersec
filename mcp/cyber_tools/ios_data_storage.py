import zipfile
import plistlib
import os


async def ios_data_storage(path: str) -> dict:
    """Check iOS app for insecure local data storage patterns."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            names = z.namelist()

            # Scan Info.plist for sensitive NSUserDefaults keys
            plist_paths = [n for n in names if n.endswith('Info.plist')]
            sensitive_keys = []
            if plist_paths:
                with z.open(plist_paths[0]) as f:
                    plist = plistlib.load(f)
                for k, v in plist.items():
                    if any(s in k.lower() for s in ['password', 'secret', 'token', 'auth', 'credential']):
                        sensitive_keys.append({"key": k, "value_preview": str(v)[:80]})

            # Scan for CoreData, sqlite, realm storage files
            storage_files = {
                "coredata": sorted(n for n in names if '.xcdatamodel' in n or '.momd' in n),
                "sqlite": sorted(n for n in names if n.endswith('.sqlite') or n.endswith('.db')),
                "realm": sorted(n for n in names if n.endswith('.realm')),
            }

            # Scan for NSKeyedArchiver / archive references
            archive_refs = []
            for n in names:
                if any(x in n.lower() for x in ['nskeyedarchiver', 'archive']):
                    if n.endswith('.plist') or n.endswith('.archive') or n.endswith('.data'):
                        archive_refs.append(n)

            return {
                "path": path,
                "app_name": os.path.basename(path),
                "sensitive_nsuserdefaults_keys": sensitive_keys,
                "sensitive_keys_count": len(sensitive_keys),
                "storage_files": storage_files,
                "storage_files_count": sum(len(v) for v in storage_files.values()),
                "archive_references": archive_refs[:20],
                "archive_references_count": len(archive_refs),
            }
    except Exception as e:
        return {"path": path, "error": str(e)}
