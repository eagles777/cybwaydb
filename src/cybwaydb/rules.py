"""Rule engine: public DISA STIG / NIST SP 800-53 checks against the
synthetic Oracle-style catalog.

References cite DISA Oracle Database 12c STIG rule families and NIST
SP 800-53 rev5 control IDs — both US Government works in the public domain.
Copyrighted third-party benchmark content is deliberately excluded
(see CLAUDE.md and LEGAL.md).

Every rule is a pure function: sqlite3.Connection -> Finding.
Deterministic, offline, $0.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field, asdict
from typing import Callable

PASS = "PASS"
FAIL = "FAIL"


@dataclass
class Finding:
    rule_id: str
    title: str
    status: str                      # PASS / FAIL
    severity: str                    # high / medium / low
    references: list[str]            # STIG / NIST citations
    evidence: list[str] = field(default_factory=list)
    remediation_sql: str = ""        # NEVER auto-executed; dry-run + human approval only

    def to_dict(self) -> dict:
        return asdict(self)


RuleFunc = Callable[[sqlite3.Connection], Finding]
RULES: list[tuple[str, RuleFunc]] = []


def rule(func: RuleFunc) -> RuleFunc:
    RULES.append((func.__name__, func))
    return func


def _profile_limit(conn: sqlite3.Connection, resource: str) -> list[tuple[str, str]]:
    return conn.execute(
        'SELECT profile, "limit" FROM dba_profiles WHERE resource_name = ?', (resource,)
    ).fetchall()


def _param(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute("SELECT value FROM v_parameter WHERE name = ?", (name,)).fetchone()
    return row[0] if row else None


def _finding(rule_id, title, ok, severity, refs, evidence, remediation_sql=""):
    return Finding(
        rule_id=rule_id,
        title=title,
        status=PASS if ok else FAIL,
        severity=severity,
        references=refs,
        evidence=evidence,
        remediation_sql="" if ok else remediation_sql,
    )


@rule
def check_failed_login_attempts(conn):
    bad = [(p, v) for p, v in _profile_limit(conn, "FAILED_LOGIN_ATTEMPTS")
           if v.upper() == "UNLIMITED" or (v.isdigit() and int(v) > 3)]
    return _finding(
        "CYB-001", "Profiles must limit consecutive failed logons to 3 or fewer",
        not bad, "medium",
        ["DISA Oracle 12c STIG SV-219899 (O121-C2-014900)", "NIST 800-53r5 AC-7"],
        [f"profile {p}: FAILED_LOGIN_ATTEMPTS={v}" for p, v in bad],
        "ALTER PROFILE {profile} LIMIT FAILED_LOGIN_ATTEMPTS 3;",
    )


@rule
def check_password_life_time(conn):
    bad = [(p, v) for p, v in _profile_limit(conn, "PASSWORD_LIFE_TIME")
           if v.upper() == "UNLIMITED" or (v.isdigit() and int(v) > 60)]
    return _finding(
        "CYB-002", "Password lifetime must be 60 days or fewer",
        not bad, "medium",
        ["DISA Oracle 12c STIG SV-219965 (O121-C2-011700)", "NIST 800-53r5 IA-5(1)"],
        [f"profile {p}: PASSWORD_LIFE_TIME={v}" for p, v in bad],
        "ALTER PROFILE {profile} LIMIT PASSWORD_LIFE_TIME 60;",
    )


@rule
def check_password_verify_function(conn):
    bad = [(p, v) for p, v in _profile_limit(conn, "PASSWORD_VERIFY_FUNCTION")
           if v.upper() in ("NULL", "NONE", "")]
    return _finding(
        "CYB-003", "A password complexity verify function must be set on every profile",
        not bad, "high",
        ["DISA Oracle 12c STIG SV-219967 (O121-C2-013800)", "NIST 800-53r5 IA-5(1)"],
        [f"profile {p}: PASSWORD_VERIFY_FUNCTION={v}" for p, v in bad],
        "ALTER PROFILE {profile} LIMIT PASSWORD_VERIFY_FUNCTION ORA12C_STIG_VERIFY_FUNCTION;",
    )


@rule
def check_password_reuse_max(conn):
    bad = [(p, v) for p, v in _profile_limit(conn, "PASSWORD_REUSE_MAX")
           if v.upper() == "UNLIMITED" or (v.isdigit() and int(v) < 5)]
    return _finding(
        "CYB-004", "Password reuse must be restricted (PASSWORD_REUSE_MAX >= 5)",
        not bad, "medium",
        ["NIST 800-53r5 IA-5(1)(e)"],
        [f"profile {p}: PASSWORD_REUSE_MAX={v}" for p, v in bad],
        "ALTER PROFILE {profile} LIMIT PASSWORD_REUSE_MAX 5;",
    )


@rule
def check_idle_time(conn):
    bad = [(p, v) for p, v in _profile_limit(conn, "IDLE_TIME")
           if v.upper() == "UNLIMITED" or (v.isdigit() and int(v) > 15)]
    return _finding(
        "CYB-005", "Idle sessions must be limited to 15 minutes",
        not bad, "medium",
        ["DISA Oracle 12c STIG SV-219839 (O121-C2-004500)", "NIST 800-53r5 SC-10"],
        [f"profile {p}: IDLE_TIME={v}" for p, v in bad],
        "ALTER PROFILE {profile} LIMIT IDLE_TIME 15;",
    )


@rule
def check_default_demo_accounts_locked(conn):
    demo = ("SCOTT", "DBSNMP", "OUTLN", "HR", "OE", "SH")
    rows = conn.execute(
        f"SELECT username, account_status FROM dba_users "
        f"WHERE username IN ({','.join('?' * len(demo))}) AND account_status = 'OPEN'",
        demo,
    ).fetchall()
    return _finding(
        "CYB-006", "Default/demonstration accounts must be locked or removed",
        not rows, "high",
        ["DISA Oracle 12c STIG SV-219869 (O121-C2-011500)", "NIST 800-53r5 AC-2, CM-6"],
        [f"{u} is {s}" for u, s in rows],
        "ALTER USER {username} ACCOUNT LOCK PASSWORD EXPIRE;",
    )


@rule
def check_expired_accounts(conn):
    rows = conn.execute(
        "SELECT username, account_status FROM dba_users "
        "WHERE account_status LIKE 'EXPIRED%' AND account_status NOT LIKE '%LOCKED%'"
    ).fetchall()
    return _finding(
        "CYB-007", "Expired accounts must also be locked (stale accounts removed)",
        not rows, "medium",
        ["NIST 800-53r5 AC-2(3)"],
        [f"{u} is {s}" for u, s in rows],
        "ALTER USER {username} ACCOUNT LOCK;",
    )


@rule
def check_dba_role_grants(conn):
    allowed = ("SYS", "SYSTEM")
    rows = conn.execute(
        f"SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA' "
        f"AND grantee NOT IN ({','.join('?' * len(allowed))})",
        allowed,
    ).fetchall()
    return _finding(
        "CYB-008", "DBA role must not be granted to non-administrative accounts",
        not rows, "high",
        ["DISA Oracle 12c STIG SV-219855 (O121-C2-006900)", "NIST 800-53r5 AC-6"],
        [f"DBA granted to {r[0]}" for r in rows],
        "REVOKE DBA FROM {grantee};",
    )


@rule
def check_public_grants(conn):
    roles = conn.execute(
        "SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC'"
    ).fetchall()
    privs = conn.execute(
        "SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC'"
    ).fetchall()
    ev = [f"PUBLIC has role {r[0]}" for r in roles] + [f"PUBLIC has privilege {p[0]}" for p in privs]
    return _finding(
        "CYB-009", "PUBLIC must not hold roles or system privileges",
        not ev, "high",
        ["DISA Oracle 12c STIG SV-219858 (O121-C2-008700)", "NIST 800-53r5 AC-6, CM-7"],
        ev,
        "REVOKE {role_or_privilege} FROM PUBLIC;",
    )


@rule
def check_any_privileges(conn):
    rows = conn.execute(
        "SELECT grantee, privilege FROM dba_sys_privs "
        "WHERE privilege LIKE '%ANY%' AND grantee NOT IN ('SYS','SYSTEM')"
    ).fetchall()
    return _finding(
        "CYB-010", "'ANY'-scoped system privileges must not be granted to ordinary users",
        not rows, "high",
        ["DISA Oracle 12c STIG SV-219853 (O121-C2-006700)", "NIST 800-53r5 AC-6(1)"],
        [f"{g} has {p}" for g, p in rows],
        "REVOKE {privilege} FROM {grantee};",
    )


@rule
def check_admin_option_grants(conn):
    rows = conn.execute(
        "SELECT grantee, privilege FROM dba_sys_privs "
        "WHERE admin_option = 'YES' AND grantee NOT IN ('SYS','SYSTEM')"
    ).fetchall()
    return _finding(
        "CYB-011", "System privileges must not be held WITH ADMIN OPTION by ordinary users",
        not rows, "medium",
        ["NIST 800-53r5 AC-6(2)"],
        [f"{g} has {p} WITH ADMIN OPTION" for g, p in rows],
        "REVOKE {privilege} FROM {grantee}; GRANT {privilege} TO {grantee};",
    )


@rule
def check_audit_trail_enabled(conn):
    v = (_param(conn, "audit_trail") or "NONE").upper()
    ok = v not in ("NONE", "FALSE")
    return _finding(
        "CYB-012", "Database auditing must be enabled (audit_trail != NONE)",
        ok, "high",
        ["DISA Oracle 12c STIG SV-219828 (O121-C2-009800)", "NIST 800-53r5 AU-2, AU-12"],
        [] if ok else [f"audit_trail={v}"],
        "ALTER SYSTEM SET audit_trail='DB,EXTENDED' SCOPE=SPFILE;",
    )


@rule
def check_logon_auditing(conn):
    row = conn.execute(
        "SELECT success, failure FROM dba_stmt_audit_opts WHERE audit_option = 'CREATE SESSION'"
    ).fetchone()
    ok = row is not None and "BY" in row[0] and "BY" in row[1]
    return _finding(
        "CYB-013", "Logon events (CREATE SESSION) must be audited for success and failure",
        ok, "medium",
        ["DISA Oracle 12c STIG SV-219833 (O121-C2-010500)", "NIST 800-53r5 AU-2, AC-7"],
        [] if ok else ["CREATE SESSION auditing not configured"],
        "AUDIT CREATE SESSION BY ACCESS;",
    )


@rule
def check_remote_login_passwordfile(conn):
    v = (_param(conn, "remote_login_passwordfile") or "").upper()
    ok = v in ("EXCLUSIVE", "NONE")
    return _finding(
        "CYB-014", "remote_login_passwordfile must be EXCLUSIVE or NONE (not SHARED)",
        ok, "medium",
        ["DISA Oracle 12c STIG SV-220016 (O121-C2-019500)", "NIST 800-53r5 IA-5, CM-6"],
        [] if ok else [f"remote_login_passwordfile={v}"],
        "ALTER SYSTEM SET remote_login_passwordfile='EXCLUSIVE' SCOPE=SPFILE;",
    )


@rule
def check_o7_dictionary_accessibility(conn):
    v = (_param(conn, "o7_dictionary_accessibility") or "FALSE").upper()
    ok = v == "FALSE"
    return _finding(
        "CYB-015", "o7_dictionary_accessibility must be FALSE",
        ok, "high",
        ["DISA Oracle 12c STIG SV-219850 (O121-C2-006500)", "NIST 800-53r5 AC-3, CM-6"],
        [] if ok else [f"o7_dictionary_accessibility={v}"],
        "ALTER SYSTEM SET o7_dictionary_accessibility=FALSE SCOPE=SPFILE;",
    )


@rule
def check_resource_limit(conn):
    v = (_param(conn, "resource_limit") or "FALSE").upper()
    ok = v == "TRUE"
    return _finding(
        "CYB-016", "resource_limit must be TRUE so profile kernel limits are enforced",
        ok, "low",
        ["NIST 800-53r5 SC-6, CM-6"],
        [] if ok else [f"resource_limit={v}"],
        "ALTER SYSTEM SET resource_limit=TRUE SCOPE=BOTH;",
    )


@rule
def check_cpu_patch_current(conn):
    from datetime import date

    from .patchwatch import patch_status

    meta = dict(conn.execute("SELECT key, value FROM db_metadata").fetchall())
    applied = meta.get("last_cpu_patch_applied")
    as_of = date.fromisoformat(meta["scan_date"]) if "scan_date" in meta else date.today()
    status = patch_status(date.fromisoformat(applied) if applied else None, as_of)
    ok = status["state"] == "CURRENT"
    return _finding(
        "CYB-017", "Database must be patched to the current Oracle CPU cycle (quarterly)",
        ok, "high",
        ["NIST 800-53r5 SI-2 (Flaw Remediation)", "FISMA/RMF continuous monitoring",
         f"Oracle CPU advisory calendar: {status['advisory']}"],
        [] if ok else [
            f"patch state: {status['state']}",
            f"last CPU applied: {status['last_patch_applied']}",
            f"current cycle: {status['current_cycle']} ({status['cycles_behind']} cycle(s) behind)",
            f"next cycle: {status['next_cycle']}",
        ],
        "-- Apply the current quarterly CPU/RU via opatch/datapatch per Oracle's advisory; "
        "then update patch inventory.",
    )


def run_all_rules(conn: sqlite3.Connection) -> list[Finding]:
    return [func(conn) for _, func in RULES]
