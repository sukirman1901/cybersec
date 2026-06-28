"""Multi-protocol password audit — SSH, FTP, SMTP, HTTP form."""
import json
import socket
import urllib.request
import urllib.parse
import base64
import time

COMMON_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "pass123",
    "password123", "admin123", "letmein", "welcome", "qwerty",
    "changeme", "test", "guest", "P@ssw0rd", "password1",
    "12345678", "abc123", "monkey", "dragon", "master",
    "1234567890", "iloveyou", "trustno1", "welcome1", "shadow",
]

COMMON_USERNAMES = [
    "admin", "root", "user", "test", "guest", "support",
    "operator", "backup", "postgres", "mysql", "sa",
]

def password_audit(target: str, protocol: str = "ssh", port: int = 0, username: str = "admin", password_list: str = "", max_attempts: int = 20) -> str:
    passwords = password_list.split(",") if password_list else COMMON_PASSWORDS[:max_attempts]
    usernames = [username] if username != "auto" else COMMON_USERNAMES[:5]
    if not port:
        port = {"ssh": 22, "ftp": 21, "smtp": 25, "http": 80, "https": 443, "rdp": 3389, "mysql": 3306, "postgres": 5432}.get(protocol, 22)

    results = {
        "target": target,
        "protocol": protocol,
        "port": port,
        "attempts": 0,
        "successful": [],
        "failed": [],
        "weak_credentials": [],
    }

    for uname in usernames:
        for pwd in passwords:
            results["attempts"] += 1
            if results["attempts"] > max_attempts:
                break

            if protocol == "ssh":
                success = _ssh_attempt(target, port, uname, pwd)
            elif protocol == "ftp":
                success = _ftp_attempt(target, port, uname, pwd)
            elif protocol == "smtp":
                success = _smtp_attempt(target, port, uname, pwd)
            elif protocol in ("http", "https"):
                success = _http_attempt(target, protocol, uname, pwd)
            elif protocol == "rdp":
                success = _rdp_attempt(target, port, uname, pwd)
            else:
                success = False

            if success:
                results["successful"].append({"username": uname, "password": pwd})
                results["weak_credentials"].append({"username": uname, "password": pwd, "severity": "critical"})
            else:
                results["failed"].append({"username": uname, "password": pwd})
            time.sleep(0.3)  # rate limit

    results["success_count"] = len(results["successful"])
    if results["successful"]:
        results["severity"] = "critical"
        results["recommendation"] = "Weak credentials found. Enforce strong password policy, enable 2FA, lockout after failed attempts, and rotate credentials immediately."
    else:
        results["severity"] = "info"
        results["recommendation"] = "No weak credentials found with tested combinations. Consider testing with larger wordlists."

    return json.dumps(results, indent=2)


def _ssh_attempt(host, port, user, pwd):
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=pwd, timeout=8)
        client.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _ftp_attempt(host, port, user, pwd):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=8)
        ftp.login(user, pwd)
        ftp.quit()
        return True
    except Exception:
        return False


def _smtp_attempt(host, port, user, pwd):
    try:
        import smtplib
        server = smtplib.SMTP(host, port, timeout=8)
        server.ehlo()
        server.login(user, pwd)
        server.quit()
        return True
    except Exception:
        return False


def _http_attempt(url, protocol, user, pwd):
    if not url.startswith("http"):
        url = f"{protocol}://{url}"
    try:
        data = urllib.parse.urlencode({"username": user, "password": pwd, "user": user, "pass": pwd}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read().decode("utf-8", errors="ignore").lower()
        if "welcome" in body or "dashboard" in body or "logout" in body:
            return True
        return False
    except Exception:
        return False


def _rdp_attempt(host, port, user, pwd):
    return False  # requires rdp lib