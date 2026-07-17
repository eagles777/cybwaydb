"""Synthetic SQLite database mimicking Oracle security catalog views.

ALL DATA IS FAKE. Usernames, hashes, and hostnames are invented for testing.
No real database, credential, or organizational data appears here.

The schema intentionally mirrors the shape of Oracle data-dictionary views
(dba_users, dba_profiles, dba_role_privs, dba_sys_privs, v$parameter,
dba_stmt_audit_opts) so the rule engine can be written against realistic
column names.
"""

from __future__ import annotations

import sqlite3

from .redteam import CANARY_COMMENT

SCHEMA = """
CREATE TABLE dba_users (
    username TEXT PRIMARY KEY,
    account_status TEXT NOT NULL,          -- OPEN / LOCKED / EXPIRED / EXPIRED & LOCKED
    profile TEXT NOT NULL,
    default_tablespace TEXT NOT NULL,
    authentication_type TEXT NOT NULL,     -- PASSWORD / EXTERNAL / GLOBAL
    created TEXT NOT NULL,
    oracle_maintained TEXT NOT NULL        -- Y / N
);

CREATE TABLE dba_profiles (
    profile TEXT NOT NULL,
    resource_name TEXT NOT NULL,           -- e.g. FAILED_LOGIN_ATTEMPTS
    resource_type TEXT NOT NULL,           -- PASSWORD / KERNEL
    "limit" TEXT NOT NULL,
    PRIMARY KEY (profile, resource_name)
);

CREATE TABLE dba_role_privs (
    grantee TEXT NOT NULL,
    granted_role TEXT NOT NULL,
    admin_option TEXT NOT NULL,            -- YES / NO
    PRIMARY KEY (grantee, granted_role)
);

CREATE TABLE dba_sys_privs (
    grantee TEXT NOT NULL,
    privilege TEXT NOT NULL,
    admin_option TEXT NOT NULL,
    PRIMARY KEY (grantee, privilege)
);

CREATE TABLE v_parameter (                 -- mirrors v$parameter
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE dba_stmt_audit_opts (
    audit_option TEXT PRIMARY KEY,
    success TEXT NOT NULL,                 -- BY ACCESS / BY SESSION / NOT SET
    failure TEXT NOT NULL
);

CREATE TABLE db_metadata (                 -- synthetic instance metadata
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE all_tab_comments (            -- mirrors all_tab_comments
    table_name TEXT PRIMARY KEY,
    comments TEXT NOT NULL
);
"""

# A deliberately non-compliant baseline so the rule engine has findings to find.
BASELINE_ROWS = {
    "dba_users": [
        # (username, status, profile, tablespace, auth, created, oracle_maintained)
        ("SYS", "OPEN", "DEFAULT", "SYSTEM", "PASSWORD", "2024-01-01", "Y"),
        ("SYSTEM", "OPEN", "DEFAULT", "SYSTEM", "PASSWORD", "2024-01-01", "Y"),
        ("SCOTT", "OPEN", "DEFAULT", "USERS", "PASSWORD", "2024-01-01", "Y"),   # demo acct, should be locked
        ("DBSNMP", "OPEN", "DEFAULT", "SYSAUX", "PASSWORD", "2024-01-01", "Y"), # should be locked
        ("OUTLN", "LOCKED", "DEFAULT", "SYSTEM", "PASSWORD", "2024-01-01", "Y"),
        ("APP_FAKE_OWNER", "OPEN", "DEFAULT", "USERS", "PASSWORD", "2024-02-10", "N"),
        ("JDOE_FAKE", "OPEN", "DEFAULT", "USERS", "PASSWORD", "2024-03-05", "N"),
        ("OLD_SVC_FAKE", "EXPIRED", "DEFAULT", "USERS", "PASSWORD", "2023-01-01", "N"),
        ("USERS_TBS_FAKE", "OPEN", "DEFAULT", "SYSTEM", "PASSWORD", "2024-04-01", "N"),  # data in SYSTEM tbs
    ],
    "dba_profiles": [
        ("DEFAULT", "FAILED_LOGIN_ATTEMPTS", "PASSWORD", "UNLIMITED"),
        ("DEFAULT", "PASSWORD_LIFE_TIME", "PASSWORD", "UNLIMITED"),
        ("DEFAULT", "PASSWORD_VERIFY_FUNCTION", "PASSWORD", "NULL"),
        ("DEFAULT", "PASSWORD_REUSE_MAX", "PASSWORD", "UNLIMITED"),
        ("DEFAULT", "PASSWORD_LOCK_TIME", "PASSWORD", ".0006"),
        ("DEFAULT", "IDLE_TIME", "KERNEL", "UNLIMITED"),
        ("DEFAULT", "SESSIONS_PER_USER", "KERNEL", "UNLIMITED"),
    ],
    "dba_role_privs": [
        ("JDOE_FAKE", "DBA", "NO"),          # excessive privilege
        ("APP_FAKE_OWNER", "RESOURCE", "NO"),
        ("APP_FAKE_OWNER", "CONNECT", "NO"),
        ("PUBLIC", "SELECT_CATALOG_ROLE", "NO"),  # role granted to PUBLIC
    ],
    "dba_sys_privs": [
        ("JDOE_FAKE", "SELECT ANY TABLE", "NO"),
        ("APP_FAKE_OWNER", "UNLIMITED TABLESPACE", "NO"),
        ("PUBLIC", "EXECUTE ANY PROCEDURE", "NO"),
        ("OLD_SVC_FAKE", "ALTER SYSTEM", "YES"),
    ],
    "v_parameter": [
        ("audit_trail", "NONE"),
        ("sec_case_sensitive_logon", "FALSE"),
        ("remote_login_passwordfile", "SHARED"),
        ("sql92_security", "FALSE"),
        ("o7_dictionary_accessibility", "TRUE"),
        ("resource_limit", "FALSE"),
    ],
    "dba_stmt_audit_opts": [
        # Intentionally sparse: logon auditing not configured.
    ],
    "db_metadata": [
        ("db_name", "FAKEDB1"),
        ("version", "19.0.0.0.0"),
        ("last_cpu_patch_applied", "2025-10-21"),  # synthetic date, 3 cycles behind
        ("scan_date", "2026-07-17"),               # frozen for deterministic tests
        ("host", "fakehost01.example.test"),
    ],
    # INJECTION CANARY: booby-trapped comment the checker must catch.
    "all_tab_comments": [
        ("EMPLOYEES_FAKE", CANARY_COMMENT),
        ("ORDERS_FAKE", "Synthetic orders table for testing."),
    ],
}


def create_synthetic_db(path: str = ":memory:", rows: dict | None = None) -> sqlite3.Connection:
    """Create the synthetic catalog DB and load rows (defaults to the
    deliberately non-compliant BASELINE_ROWS)."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    data = BASELINE_ROWS if rows is None else rows
    for table, tuples in data.items():
        if not tuples:
            continue
        placeholders = ",".join("?" * len(tuples[0]))
        conn.executemany(f"INSERT INTO {table} VALUES ({placeholders})", tuples)
    conn.commit()
    return conn


def compliant_rows() -> dict:
    """A hardened variant of the baseline, used by tests to prove rules
    pass when the configuration is compliant."""
    return {
        "dba_users": [
            ("SYS", "OPEN", "SECURE_PROFILE", "SYSTEM", "PASSWORD", "2024-01-01", "Y"),
            ("SYSTEM", "OPEN", "SECURE_PROFILE", "SYSTEM", "PASSWORD", "2024-01-01", "Y"),
            ("SCOTT", "EXPIRED & LOCKED", "SECURE_PROFILE", "USERS", "PASSWORD", "2024-01-01", "Y"),
            ("DBSNMP", "LOCKED", "SECURE_PROFILE", "SYSAUX", "PASSWORD", "2024-01-01", "Y"),
            ("APP_FAKE_OWNER", "OPEN", "SECURE_PROFILE", "USERS", "PASSWORD", "2024-02-10", "N"),
        ],
        "dba_profiles": [
            ("SECURE_PROFILE", "FAILED_LOGIN_ATTEMPTS", "PASSWORD", "3"),
            ("SECURE_PROFILE", "PASSWORD_LIFE_TIME", "PASSWORD", "60"),
            ("SECURE_PROFILE", "PASSWORD_VERIFY_FUNCTION", "PASSWORD", "ORA12C_STIG_VERIFY_FUNCTION"),
            ("SECURE_PROFILE", "PASSWORD_REUSE_MAX", "PASSWORD", "5"),
            ("SECURE_PROFILE", "PASSWORD_LOCK_TIME", "PASSWORD", "UNLIMITED"),
            ("SECURE_PROFILE", "IDLE_TIME", "KERNEL", "15"),
            ("SECURE_PROFILE", "SESSIONS_PER_USER", "KERNEL", "10"),
        ],
        "dba_role_privs": [
            ("APP_FAKE_OWNER", "CONNECT", "NO"),
        ],
        "dba_sys_privs": [
            ("APP_FAKE_OWNER", "CREATE SESSION", "NO"),
        ],
        "v_parameter": [
            ("audit_trail", "DB,EXTENDED"),
            ("sec_case_sensitive_logon", "TRUE"),
            ("remote_login_passwordfile", "EXCLUSIVE"),
            ("sql92_security", "TRUE"),
            ("o7_dictionary_accessibility", "FALSE"),
            ("resource_limit", "TRUE"),
        ],
        "dba_stmt_audit_opts": [
            ("CREATE SESSION", "BY ACCESS", "BY ACCESS"),
        ],
        "db_metadata": [
            ("db_name", "FAKEDB1"),
            ("version", "19.0.0.0.0"),
            ("last_cpu_patch_applied", "2026-07-14"),  # = July 2026 CPU date
            ("scan_date", "2026-07-17"),
            ("host", "fakehost01.example.test"),
        ],
        "all_tab_comments": [
            ("ORDERS_FAKE", "Synthetic orders table for testing."),
        ],
    }
