"""Multi-protocol password audit — SSH, FTP, SMTP, HTTP form."""
import json
import ipaddress
import re
import urllib.request
import urllib.parse
import time
from .http_guard import guarded_urlopen

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


def _safe_target(target):
    if not isinstance(target, str) or len(target) > 2048:
        return "[REDACTED]"
    try:
        parsed = urllib.parse.urlsplit(target if "://" in target else "//" + target)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", "")) if parsed.scheme else host + parsed.path
    except ValueError:
        return "[REDACTED]"


def _valid_host(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in host.rstrip('.').split('.'))


def password_audit(target: str, protocol: str = "ssh", port: int = 0, username: str = "admin", password_list: str = "", max_attempts: int = 20) -> str:
    invalid = {"target": _safe_target(target), "attempts": 0, "successful": [], "failed": [],
               "weak_credentials": [], "candidates": [], "incomplete": [], "success_count": 0,
               "coverage_complete": False, "error": "Invalid or oversized arguments",
               "coverage": "No authentication attempted", "confidence": "LOW"}
    if (type(max_attempts) is not int or type(port) is not int or not 0 <= port <= 65535
            or not isinstance(protocol, str) or len(protocol) > 16
            or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}", username)
            or not isinstance(password_list, str) or len(password_list) > 81920
            or len(password_list.encode('utf-8', errors='replace')) > 81920
            or any(c in password_list for c in '\x00\r\n')
            or any(len(p.encode('utf-8', errors='replace')) > 4096 for p in password_list.split(','))
            or not isinstance(target, str) or not target or len(target) > 2048
            or any(c.isspace() or ord(c) < 32 for c in target)):
        return json.dumps(invalid)
    if protocol in ("http", "https"):
        try:
            parsed = urllib.parse.urlsplit(target if "://" in target else f"{protocol}://{target}")
            valid_target = (parsed.scheme == protocol and _valid_host(parsed.hostname)
                            and parsed.username is None and parsed.password is None
                            and (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            valid_target = False
    else:
        valid_target = _valid_host(target)
    if not valid_target:
        return json.dumps(invalid)
    limit = min(20, max(0, max_attempts))
    passwords = password_list.split(",", limit)[:limit] if password_list else COMMON_PASSWORDS[:limit]
    usernames = [username] if username != "auto" else COMMON_USERNAMES[:5]
    if not port:
        port = {"ssh": 22, "ftp": 21, "smtp": 25, "http": 80, "https": 443, "rdp": 3389, "mysql": 3306, "postgres": 5432}.get(protocol, 22)

    results = {
        "target": _safe_target(target),
        "protocol": protocol,
        "port": port,
        "attempts": 0,
        "successful": [],
        "failed": [],
        "weak_credentials": [],
        "candidates": [],
        "incomplete": [],
        "attempt_limit": limit,
        "coverage_complete": False,
        "coverage": "Bounded supplied combinations only; attempts count adapter invocations, not confirmed server logins.",
    }

    supported = protocol in ("ssh", "ftp", "smtp", "http", "https")
    if not supported or not limit:
        results["error"] = "Unsupported protocol" if not supported else "No attempt budget"
        usernames = []
    for uname in usernames:
        for pwd in passwords:
            if results["attempts"] >= limit:
                break
            results["attempts"] += 1
            try:
                if protocol in ("http", "https"):
                    success = _http_attempt(target, protocol, uname, pwd)
                else:
                    success = {"ssh": _ssh_attempt, "ftp": _ftp_attempt, "smtp": _smtp_attempt}[protocol](target, port, uname, pwd)
            except Exception:
                success = None
            record = {"attempt_index": results["attempts"], "username": "[REDACTED]", "password": "[REDACTED]"}
            if success is True:
                record.update(confidence="HIGH", coverage=f"{protocol} password authentication accepted for this indexed attempt only")
                results["successful"].append(record)
                results["weak_credentials"].append({**record, "severity": "critical"})
            elif success is False:
                results["failed"].append(record)
            elif success == "candidate":
                record.update(confidence="LOW", coverage="HTTP response keywords only; authenticated session unverified")
                results["candidates"].append(record)
            else:
                results["incomplete"].append(record)
                break  # Do not repeat attempts after dependency/transport/cleanup failures.
            time.sleep(0.3)  # rate limit
        if results["attempts"] >= limit or results["incomplete"]:
            break

    results["coverage_complete"] = bool(results["attempts"] and not results["incomplete"] and not results["candidates"] and protocol not in ("http", "https"))
    results["success_count"] = len(results["successful"])
    if results["successful"]:
        results["severity"] = "critical"
        results["recommendation"] = "Weak credentials found. Enforce strong password policy, enable 2FA, lockout after failed attempts, and rotate credentials immediately."
    else:
        results["severity"] = "info" if results["coverage_complete"] else "unknown"
        results["recommendation"] = "No successful authentication observed in the bounded test." if results["coverage_complete"] else "Assessment incomplete; authentication could not be determined for all bounded attempts."

    return json.dumps(results, indent=2)


def _ssh_attempt(host, port, user, pwd):
    client = None
    try:
        import paramiko
    except ImportError:
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=pwd, timeout=8,
                       allow_agent=False, look_for_keys=False, banner_timeout=8, auth_timeout=8)
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None
    finally:
        if client is not None:
            client.close()


def _ftp_attempt(host, port, user, pwd):
    import ftplib
    ftp = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=8)
        ftp.login(user, pwd)
        return True
    except ftplib.error_perm as exc:
        return False if str(exc).startswith('530') else None
    except Exception:
        return None
    finally:
        if ftp is not None:
            ftp.close()


def _smtp_attempt(host, port, user, pwd):
    import smtplib
    server = None
    try:
        server = smtplib.SMTP(host, port, timeout=8)
        server.ehlo()
        server.login(user, pwd)
        return True
    except smtplib.SMTPAuthenticationError as exc:
        return False if exc.smtp_code == 535 else None
    except Exception:
        return None
    finally:
        if server is not None:
            server.close()


def _http_attempt(url, protocol, user, pwd):
    if not url.startswith("http"):
        url = f"{protocol}://{url}"
    resp = None
    try:
        data = urllib.parse.urlencode({"username": user, "password": pwd, "user": user, "pass": pwd}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        resp = guarded_urlopen(req, timeout=8)
        body = resp.read(65537).decode("utf-8", errors="ignore").lower()
        if "welcome" in body or "dashboard" in body or "logout" in body:
            return "candidate"
        return None
    except Exception:
        return None
    finally:
        if resp is not None:
            resp.close()


def _rdp_attempt(host, port, user, pwd):
    return None  # unsupported; not an authentication rejection
