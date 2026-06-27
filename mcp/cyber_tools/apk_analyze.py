import httpx
import re
import zipfile
import io


async def apk_analyze(target: str) -> dict:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(target)
            if resp.status_code != 200 or len(resp.content) < 1000:
                return {"target": target, "error": "Could not download APK", "findings": []}
            data = io.BytesIO(resp.content)
            if not zipfile.is_zipfile(data):
                return {"target": target, "error": "Not a valid APK (ZIP) file", "findings": []}
            with zipfile.ZipFile(data) as zf:
                names = zf.namelist()
                findings.append({"finding": f"APK entries: {len(names)}", "severity": "info"})
                if "AndroidManifest.xml" in names:
                    manifest_raw = zf.read("AndroidManifest.xml")
                    manifest_text = manifest_raw.decode("utf-8", errors="replace")
                    permissions = re.findall(r'permission\.(\w+)', manifest_text)
                    if permissions:
                        dang_perms = ["INTERNET", "READ_SMS", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE"]
                        found_danger = [p for p in permissions if p in dang_perms]
                        findings.append({"finding": "Permissions declared", "permissions": permissions[:20], "dangerous": found_danger, "severity": "medium" if found_danger else "info"})
                    if "android:exported=\"true\"" in manifest_text:
                        exported = re.findall(r'activity.*?exported="true".*?name="([^"]*)"', manifest_text[:5000])
                        findings.append({"finding": f"Exported activities: {exported}", "severity": "high"})
                for suspicious_name in ["classes.dex", "lib/armeabi", "lib/arm64"]:
                    if suspicious_name in names:
                        findings.append({"finding": f"Contains: {suspicious_name}", "severity": "info"})
                pkg_name = re.search(r'package="([^"]+)"', manifest_text[:2000]) if "AndroidManifest.xml" in names else None
                pkg = pkg_name.group(1) if pkg_name else "unknown"
                return {"target": target, "package": pkg, "permissions_count": len(permissions) if 'permissions' in dir() else 0, "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"target": target, "error": str(e), "findings": findings}
