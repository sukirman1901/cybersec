import zipfile
import plistlib
import os


async def ios_signing(path: str) -> dict:
    """Check iOS app signing — provisioning profile, team ID, ad-hoc vs distribution."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            names = z.namelist()
            result = {}

            # Extract CFBundleIdentifier from Info.plist
            plist_paths = [n for n in names if n.endswith('Info.plist')]
            if plist_paths:
                with z.open(plist_paths[0]) as f:
                    plist = plistlib.load(f)
                result["bundle_identifier"] = plist.get("CFBundleIdentifier", "unknown")

            # Extract and parse embedded.mobileprovision
            provision_paths = [n for n in names if 'embedded.mobileprovision' in n]
            if provision_paths:
                with z.open(provision_paths[0]) as f:
                    data = f.read()

                # Parse XML plist from within the binary CMS blob
                text = data.decode("utf-8", errors="replace")
                xml_start = text.find("<?xml")
                if xml_start >= 0:
                    xml_end = text.find("</plist>", xml_start)
                    if xml_end >= 0:
                        xml_content = text[xml_start:xml_end + len("</plist>")]
                        try:
                            provision = plistlib.loads(xml_content.encode("utf-8"))
                            result["app_id_name"] = provision.get("AppIDName", "N/A")
                            result["team_name"] = provision.get("TeamName", "N/A")
                            result["creation_date"] = str(provision.get("CreationDate", "N/A"))
                            result["expiration_date"] = str(provision.get("ExpirationDate", "N/A"))
                            result["platform"] = provision.get("Platform", [])
                            result["entitlements"] = provision.get("Entitlements", {})
                            result["provisioned_devices"] = provision.get("ProvisionedDevices", [])
                            result["is_adhoc"] = "ProvisionedDevices" in provision
                        except Exception:
                            result["provision_error"] = "Failed to parse provisioning profile XML"
                else:
                    result["provision_error"] = "No XML plist found in embedded.mobileprovision"
            else:
                result["provision_error"] = "No embedded.mobileprovision found in IPA"

            return {
                "path": path,
                "app_name": os.path.basename(path),
                **result,
            }
    except Exception as e:
        return {"path": path, "error": str(e)}
