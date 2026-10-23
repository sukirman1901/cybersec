"""SQLi detection using repeated baseline/control experiments.

The MCP signature is unchanged. This slice confirms error-based and boolean
GET/query evidence; timing, UNION and extraction are explicitly not executed.
"""

import httpx  # Kept for existing transport instrumentation/patching.

from .sqli_probe import scan_query


SQL_ERRORS = [
    r"SQL syntax[^\r\n]{0,160}MySQL",
    r"Warning[^\r\n]{0,160}mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"MySqlClient\.",
    r"PostgreSQL[^\r\n]{0,160}ERROR",
    r"Warning[^\r\n]{0,160}\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    r"Microsoft[^\r\n]{0,80}ODBC[^\r\n]{0,80}SQL Server",
    r"Driver[^\r\n]{0,160}SQL Server",
    r"SQLServer JDBC",
    r"Unclosed quotation mark after the character string",
    r"SQLSTATE\[42000\]",
    r"Microsoft SQL Native Client error",
    r"mssql_query\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite",
    r"SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"ORA-[0-9]{5}",
    r"Oracle[^\r\n]{0,160}driver",
    r"oracle\.jdbc",
    r"Informix",
    r"CLI Driver[^\r\n]{0,160}DB2",
    r"DB2 SQL error",
    r"SQL Anywhere",
    r"Sybase",
    r"Teradata",
    r"Vertica",
    r"Impala",
    r"Hive\.QL",
]


async def sqli_detect(target: str, param: str = "", preset: str = "observe-first") -> dict:
    """Confirm GET/query SQLi using repeated baselines, controls and paired probes.

    observe-first: at most 2 parameter occurrences, 80 requests, 18 seconds.
    staging-deep: at most 4 occurrences, 160 requests, 55 seconds.
    Results distinguish confirmed findings, candidates and inconclusive coverage.
    Timing/UNION, POST/JSON/cookies and data extraction are not executed here.
    """
    return await scan_query(target, param, preset, SQL_ERRORS)
