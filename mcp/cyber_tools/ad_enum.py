"""
Active Directory enumeration tool using impacket's LDAP.
Enumerates users, groups, computers, trusts, and password policy.
Returns structured dicts suitable for MCP tool responses.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from impacket.ldap import ldap, ldapasn1 as ldapasn1_impacket
from impacket.examples.utils import ldap_login
from impacket.examples import logger as impacket_logger

# Suppress impacket's noisy LDAP logging
logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


def _entry_to_dict(entry: Any) -> dict:
    """Convert an impacket SearchResultEntry to a plain dict for _extract."""
    out: dict[str, Any] = {}
    try:
        for attr in entry["attributes"]:
            attr_type = str(attr["type"])
            vals = []
            for v in attr["vals"]:
                try:
                    vals.append(v.asOctets().decode("utf-8", errors="replace"))
                except (AttributeError, Exception):
                    vals.append(str(v))
            out[attr_type] = vals
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode(value: Any) -> str:
    """Safely decode an LDAP attribute value to a plain string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _extract(entry: Any, names: list[str]) -> dict:
    """Extract attributes from an LDAP entry into a plain dict.

    Multi-valued attributes are returned as lists; single-valued as plain
    strings.  Missing attributes become ``None``.
    """
    out: dict[str, Any] = {}
    for name in names:
        try:
            raw = entry.get(name, [])
        except Exception:
            out[name] = None
            continue

        if raw is None or raw == []:
            out[name] = None
        elif len(raw) == 1:
            out[name] = _decode(raw[0])
        else:
            out[name] = [_decode(v) for v in raw]
    return out


def _parse_timedelta(raw: str | None) -> str | None:
    """Convert an AD 100-ns interval to a human-readable string.

    Returns e.g. ``"42d 12h 30m"`` or ``"None"`` for zero/empty.
    """
    if raw is None:
        return None
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return str(raw)

    if val == 0:
        return "None"
    # AD uses negative values for "never expires" semantically
    if val < 0:
        val = -val

    seconds = val / 10_000_000
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    return " ".join(parts) or f"{int(seconds)}s"


def _parse_pwd_last_set(raw: str | None) -> str | None:
    """Convert pwdLastSet (1601-01-01 epoch, 100-ns intervals) to ISO-ish UTC."""
    if raw is None:
        return None
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return str(raw)
    if val == 0:
        return "Never"
    epoch = datetime(1601, 1, 1)
    dt = epoch + timedelta(seconds=val / 10_000_000)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_uac(raw: str | None) -> list[str]:
    """Decode *userAccountControl* integer into readable flag names."""
    if raw is None:
        return []
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return [str(raw)]

    flags: list[str] = []
    # fmt: off
    bits = [
        (0x000001, "ACCOUNT_DISABLED"), (0x000002, "HOMEDIR_REQUIRED"),
        (0x000004, "LOCKOUT"), (0x000008, "PASSWD_NOTREQD"),
        (0x000010, "PASSWD_CANT_CHANGE"), (0x000020, "ENCRYPTED_TEXT_PWD_ALLOWED"),
        (0x000040, "TEMP_DUPLICATE_ACCOUNT"), (0x000080, "NORMAL_ACCOUNT"),
        (0x000100, "INTERDOMAIN_TRUST_ACCOUNT"), (0x000200, "WORKSTATION_TRUST_ACCOUNT"),
        (0x000400, "SERVER_TRUST_ACCOUNT"), (0x001000, "DONT_EXPIRE_PASSWORD"),
        (0x002000, "MNS_LOGON_ACCOUNT"), (0x004000, "SMARTCARD_REQUIRED"),
        (0x008000, "TRUSTED_FOR_DELEGATION"), (0x010000, "NOT_DELEGATED"),
        (0x020000, "USE_DES_KEY_ONLY"), (0x040000, "DONT_REQ_PREAUTH"),
        (0x080000, "PASSWORD_EXPIRED"), (0x100000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
        (0x200000, "PARTIAL_SECRETS_ACCOUNT"),
    ]
    # fmt: on
    for bit, label in bits:
        if val & bit:
            flags.append(label)
    return flags


def _trust_type(raw: str | None) -> str:
    if raw is None:
        return "Unknown"
    try:
        return {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT (Kerberos)", 4: "DCE"}.get(
            int(raw), f"Unknown ({raw})"
        )
    except (ValueError, TypeError):
        return str(raw)


def _trust_direction(raw: str | None) -> str:
    if raw is None:
        return "Unknown"
    try:
        return {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(
            int(raw), f"Unknown ({raw})"
        )
    except (ValueError, TypeError):
        return str(raw)


def _trust_attrs(raw: str | None) -> list[str]:
    """Decode *trustAttributes* bitfield."""
    if raw is None:
        return []
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return [str(raw)]
    labels = [
        (0x0001, "NON_TRANSITIVE"),
        (0x0002, "UPLEVEL_ONLY"),
        (0x0004, "QUARANTINED_DOMAIN"),
        (0x0008, "FOREST_TRANSITIVE"),
        (0x0010, "CROSS_ORGANIZATION"),
        (0x0020, "WITHIN_FOREST"),
        (0x0040, "TREAT_AS_EXTERNAL"),
        (0x0080, "USES_RSA_PRINCIPAL"),
        (0x0200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
        (0x0400, "PIM_TRUST"),
    ]
    out = [label for bit, label in labels if val & bit]
    return out or ["None"]


def _group_type(raw: str | None) -> str:
    if raw is None:
        return "Distribution"
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return "Unknown"
    kind = "Security" if val & 0x80000000 else "Distribution"
    if val & 0x00000002:
        kind += " (Global)"
    elif val & 0x00000004:
        kind += " (Domain Local)"
    elif val & 0x00000008:
        kind += " (Universal)"
    else:
        kind += " (Builtin)"
    return kind


def _make_search_base(domain: str) -> str:
    """Convert ``example.local`` → ``DC=example,DC=local``."""
    return "DC=" + ",DC=".join(domain.split("."))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def ad_enum(
    domain: str,
    dc_ip: str,
    username: str = "",
    password: str = "",
    enum_users: bool = True,
    enum_groups: bool = True,
    enum_computers: bool = True,
    enum_trusts: bool = True,
) -> dict:
    """Comprehensive Active Directory enumeration via LDAP.

    Connects to a DC, optionally authenticates, and gathers information about
    users, groups, computers, domain trusts, and the domain password policy.

    Args:
        domain: AD domain FQDN (e.g. ``"example.local"``).
        dc_ip:  IP address (or hostname) of a domain controller.
        username: Optional bind DN / username (empty = anonymous).
        password: Optional password.
        enum_users: Gather user objects (default ``True``).
        enum_groups: Gather group objects (default ``True``).
        enum_computers: Gather computer objects (default ``True``).
        enum_trusts: Gather trusted-domain objects (default ``True``).

    Returns:
        A dict with the following top-level keys:

        - ``domain`` / ``dc_ip`` / ``authenticated``  — metadata
        - ``users`` — list of user dicts
        - ``groups`` — list of group dicts
        - ``computers`` — list of computer dicts
        - ``trusts`` — list of trusted-domain dicts
        - ``password_policy`` — dict of domain password policy settings
        - ``counts`` — summary counts per category
        - ``error`` — top-level error message (or ``None`` on success)
    """
    result: dict[str, Any] = {
        "domain": domain,
        "dc_ip": dc_ip,
        "authenticated": bool(username and password),
        "users": [],
        "groups": [],
        "computers": [],
        "trusts": [],
        "password_policy": {},
        "counts": {},
        "error": None,
    }

    ldap_conn = None
    try:
        base = _make_search_base(domain)
        bind_user = username or f"anonymous@{domain}"
        ldap_conn = ldap_login(
            None, base, dc_ip, None, False,
            bind_user, password, domain, "", "", "",
        )

        # ---- Password policy ------------------------------------------------
        try:
            pw_attrs = [
                "minPwdLength",
                "maxPwdAge",
                "minPwdAge",
                "pwdHistoryLength",
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
                "pwdProperties",
            ]
            for item in ldap_conn.search(searchFilter="(objectClass=domainDNS)", attributes=pw_attrs):
                if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                    continue
                entry = _entry_to_dict(item)
                data = _extract(entry, pw_attrs)
                pp = {
                    "min_pwd_length": data.get("minPwdLength"),
                    "max_pwd_age": _parse_timedelta(data.get("maxPwdAge")),
                    "min_pwd_age": _parse_timedelta(data.get("minPwdAge")),
                    "pwd_history_length": data.get("pwdHistoryLength"),
                    "lockout_threshold": data.get("lockoutThreshold"),
                    "lockout_duration": _parse_timedelta(data.get("lockoutDuration")),
                    "lockout_observation_window": _parse_timedelta(data.get("lockOutObservationWindow")),
                    "complexity_enabled": None,
                    "reversible_encryption": None,
                }
                if data.get("pwdProperties") is not None:
                    try:
                        p = int(data["pwdProperties"])
                        pp["complexity_enabled"] = bool(p & 0x0001)
                        pp["reversible_encryption"] = bool(p & 0x0002)
                    except (ValueError, TypeError):
                        pass
                result["password_policy"] = pp
                break  # only one domainDNS object
        except Exception as exc:
            result["password_policy"]["error"] = str(exc)

        # ---- Users ----------------------------------------------------------
        if enum_users:
            try:
                u_attrs = [
                    "sAMAccountName",
                    "userPrincipalName",
                    "mail",
                    "description",
                    "memberOf",
                    "servicePrincipalName",
                    "pwdLastSet",
                    "userAccountControl",
                    "distinguishedName",
                    "cn",
                    "whenCreated",
                    "whenChanged",
                    "displayName",
                    "title",
                    "department",
                    "manager",
                    "telephoneNumber",
                    "lastLogonTimestamp",
                    "badPwdCount",
                ]
                for item in ldap_conn.search(searchFilter="(objectClass=user)", attributes=u_attrs):
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    entry = _entry_to_dict(item)
                    data = _extract(entry, u_attrs)
                    # Skip computer accounts (also have objectClass=user)
                    sam = data.get("sAMAccountName")
                    if sam and isinstance(sam, str) and sam.endswith("$"):
                        continue

                    spn = data.get("servicePrincipalName", [])
                    spn_count = len(spn) if isinstance(spn, list) else (1 if spn else 0)
                    member_of = data.get("memberOf", [])
                    mo_count = len(member_of) if isinstance(member_of, list) else (1 if member_of else 0)

                    result["users"].append(
                        {
                            "sam_account_name": sam,
                            "user_principal_name": data.get("userPrincipalName"),
                            "display_name": data.get("displayName"),
                            "cn": data.get("cn"),
                            "email": data.get("mail"),
                            "description": data.get("description"),
                            "title": data.get("title"),
                            "department": data.get("department"),
                            "telephone": data.get("telephoneNumber"),
                            "manager": data.get("manager"),
                            "distinguished_name": data.get("distinguishedName"),
                            "when_created": data.get("whenCreated"),
                            "when_changed": data.get("whenChanged"),
                            "pwd_last_set": _parse_pwd_last_set(data.get("pwdLastSet")),
                            "last_logon_timestamp": data.get("lastLogonTimestamp"),
                            "bad_pwd_count": data.get("badPwdCount"),
                            "account_control_flags": _parse_uac(data.get("userAccountControl")),
                            "spn_count": spn_count,
                            "has_spn": bool(spn),
                            "member_of_count": mo_count,
                        }
                    )
            except Exception as exc:
                result["users_error"] = str(exc)

        # ---- Groups ---------------------------------------------------------
        if enum_groups:
            try:
                g_attrs = [
                    "sAMAccountName",
                    "description",
                    "member",
                    "groupType",
                    "distinguishedName",
                    "cn",
                    "whenCreated",
                    "whenChanged",
                    "adminCount",
                    "objectSid",
                ]
                for item in ldap_conn.search(searchFilter="(objectClass=group)", attributes=g_attrs):
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    entry = _entry_to_dict(item)
                    data = _extract(entry, g_attrs)
                    members = data.get("member", [])
                    member_count = len(members) if isinstance(members, list) else (1 if members else 0)

                    result["groups"].append(
                        {
                            "sam_account_name": data.get("sAMAccountName"),
                            "cn": data.get("cn"),
                            "description": data.get("description"),
                            "distinguished_name": data.get("distinguishedName"),
                            "group_type": _group_type(data.get("groupType")),
                            "member_count": member_count,
                            "admin_count": data.get("adminCount"),
                            "when_created": data.get("whenCreated"),
                            "when_changed": data.get("whenChanged"),
                        }
                    )
            except Exception as exc:
                result["groups_error"] = str(exc)

        # ---- Computers ------------------------------------------------------
        if enum_computers:
            try:
                c_attrs = [
                    "sAMAccountName",
                    "dNSHostName",
                    "operatingSystem",
                    "operatingSystemVersion",
                    "description",
                    "distinguishedName",
                    "cn",
                    "whenCreated",
                    "whenChanged",
                    "userAccountControl",
                    "lastLogonTimestamp",
                    "pwdLastSet",
                    "badPwdCount",
                ]
                for item in ldap_conn.search(searchFilter="(objectClass=computer)", attributes=c_attrs):
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    entry = _entry_to_dict(item)
                    data = _extract(entry, c_attrs)
                    result["computers"].append(
                        {
                            "sam_account_name": data.get("sAMAccountName"),
                            "cn": data.get("cn"),
                            "dns_host_name": data.get("dNSHostName"),
                            "operating_system": data.get("operatingSystem"),
                            "operating_system_version": data.get("operatingSystemVersion"),
                            "description": data.get("description"),
                            "distinguished_name": data.get("distinguishedName"),
                            "when_created": data.get("whenCreated"),
                            "when_changed": data.get("whenChanged"),
                            "account_control_flags": _parse_uac(data.get("userAccountControl")),
                            "last_logon_timestamp": data.get("lastLogonTimestamp"),
                            "pwd_last_set": _parse_pwd_last_set(data.get("pwdLastSet")),
                            "bad_pwd_count": data.get("badPwdCount"),
                        }
                    )
            except Exception as exc:
                result["computers_error"] = str(exc)

        # ---- Domain trusts --------------------------------------------------
        if enum_trusts:
            try:
                t_attrs = [
                    "cn",
                    "trustType",
                    "trustDirection",
                    "trustAttributes",
                    "flatName",
                    "securityIdentifier",
                    "distinguishedName",
                    "whenCreated",
                    "whenChanged",
                    "trustPartner",
                ]
                for item in ldap_conn.search(searchFilter="(objectClass=trustedDomain)", attributes=t_attrs):
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    entry = _entry_to_dict(item)
                    data = _extract(entry, t_attrs)
                    result["trusts"].append(
                        {
                            "cn": data.get("cn"),
                            "flat_name": data.get("flatName"),
                            "trust_partner": data.get("trustPartner"),
                            "trust_type": _trust_type(data.get("trustType")),
                            "trust_direction": _trust_direction(data.get("trustDirection")),
                            "trust_attributes": _trust_attrs(data.get("trustAttributes")),
                            "security_identifier": data.get("securityIdentifier"),
                            "distinguished_name": data.get("distinguishedName"),
                            "when_created": data.get("whenCreated"),
                            "when_changed": data.get("whenChanged"),
                        }
                    )
            except Exception as exc:
                result["trusts_error"] = str(exc)

    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if ldap_conn is not None:
            try:
                ldap_conn.close()
            except Exception:
                pass

    result["counts"] = {
        "users": len(result["users"]),
        "groups": len(result["groups"]),
        "computers": len(result["computers"]),
        "trusts": len(result["trusts"]),
    }
    return result
