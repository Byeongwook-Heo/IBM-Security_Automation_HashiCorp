from __future__ import annotations

from contextlib import AbstractContextManager
import os
from pathlib import Path
import re
import sqlite3
from typing import Any


_NAMED_PARAMETER = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")


def is_postgres_target(target: str) -> bool:
    return target.startswith(("postgres://", "postgresql://"))


def database_target_from_env() -> str:
    url_file = os.getenv("CASE_DATABASE_URL_FILE", "").strip()
    if url_file:
        path = Path(url_file).expanduser()
        if not path.is_file():
            raise RuntimeError("CASE_DATABASE_URL_FILE does not exist")
        configured = path.read_text(encoding="utf-8").strip()
        if not is_postgres_target(configured):
            raise RuntimeError("CASE_DATABASE_URL_FILE must contain a PostgreSQL URL")
        return configured

    configured_url = os.getenv("CASE_DATABASE_URL", "").strip()
    if configured_url:
        if not is_postgres_target(configured_url):
            raise RuntimeError("CASE_DATABASE_URL must be a PostgreSQL URL")
        return configured_url

    configured_path = os.getenv("CASE_DB_PATH", "").strip()
    if configured_path:
        return configured_path
    data_home = os.getenv("XDG_DATA_HOME", "").strip()
    base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    if not base.is_absolute():
        base = Path.home() / base
    return str(base / "security-portal" / "cases.db")


def _translate_postgres_sql(statement: str, parameters: Any) -> str:
    normalized = statement.strip().upper()
    if normalized == "BEGIN IMMEDIATE":
        return "BEGIN"
    if isinstance(parameters, dict):
        return _NAMED_PARAMETER.sub(r"%(\1)s", statement)

    translated: list[str] = []
    in_single_quote = False
    index = 0
    while index < len(statement):
        character = statement[index]
        if character == "'":
            translated.append(character)
            if in_single_quote and index + 1 < len(statement) and statement[index + 1] == "'":
                translated.append("'")
                index += 2
                continue
            in_single_quote = not in_single_quote
        elif character == "?" and not in_single_quote:
            translated.append("%s")
        else:
            translated.append(character)
        index += 1
    return "".join(translated)


class DatabaseConnection(AbstractContextManager["DatabaseConnection"]):
    def __init__(self, target: str):
        self.target = target
        self.postgres = is_postgres_target(target)
        if self.postgres:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:  # pragma: no cover - packaging guard
                raise RuntimeError("PostgreSQL persistence requires psycopg") from exc
            self.raw = psycopg.connect(
                target,
                connect_timeout=5,
                row_factory=dict_row,
                application_name="security-portal",
            )
        else:
            connection = sqlite3.connect(target, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self.raw = connection

    def __enter__(self) -> "DatabaseConnection":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if exc_type is None:
            self.raw.commit()
        else:
            self.raw.rollback()
        self.raw.close()
        return False

    def execute(self, statement: str, parameters: Any = None):
        if self.postgres:
            normalized = statement.strip().upper()
            if normalized.startswith("PRAGMA "):
                raise RuntimeError("SQLite PRAGMA cannot run on PostgreSQL")
            statement = _translate_postgres_sql(statement, parameters)
        if parameters is None:
            return self.raw.execute(statement)
        return self.raw.execute(statement, parameters)

    def executescript(self, script: str) -> None:
        if not self.postgres:
            self.raw.executescript(script)
            return
        for statement in script.split(";"):
            if statement.strip():
                self.raw.execute(statement)


def connect_database(target: str) -> DatabaseConnection:
    return DatabaseConnection(target)
