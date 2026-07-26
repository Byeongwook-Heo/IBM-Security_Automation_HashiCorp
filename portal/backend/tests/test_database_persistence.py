from pathlib import Path

import pytest

from app import case_management
from app.case_management import CaseRepository, case_db_path_from_env
from app.database import _translate_postgres_sql, is_postgres_target
from app.models import CaseCreateRequest


def test_database_target_prefers_secret_file(monkeypatch, tmp_path: Path):
    secret_file = tmp_path / "database-url"
    secret_file.write_text(
        "postgresql://portal:secret@database.internal/security_portal?sslmode=require\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CASE_DATABASE_URL_FILE", str(secret_file))
    monkeypatch.setenv("CASE_DB_PATH", str(tmp_path / "ignored.db"))

    target = case_db_path_from_env()

    assert is_postgres_target(target)
    assert target.startswith("postgresql://")


def test_database_target_rejects_non_postgres_secret_file(monkeypatch, tmp_path: Path):
    secret_file = tmp_path / "database-url"
    secret_file.write_text(str(tmp_path / "cases.db"), encoding="utf-8")
    monkeypatch.setenv("CASE_DATABASE_URL_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="PostgreSQL URL"):
        case_db_path_from_env()


def test_postgres_parameter_translation_preserves_literals():
    statement = "SELECT '?' AS literal, id FROM cases WHERE id = ? AND owner = ?"

    translated = _translate_postgres_sql(statement, ("case-1", "owner@example.com"))

    assert translated == "SELECT '?' AS literal, id FROM cases WHERE id = %s AND owner = %s"


def test_sqlite_case_repository_remains_supported(tmp_path: Path):
    repository = CaseRepository(str(tmp_path / "cases.db"))

    created = repository.create(
        CaseCreateRequest(
            title="Persistence QA",
            description="SQLite remains the fail-safe local backend.",
            severity="low",
        ),
        "qa@example.com",
    )

    assert repository.get(created["id"])["title"] == "Persistence QA"


def test_postgres_initialization_skips_sqlite_file_lock(monkeypatch):
    class FakePostgresConnection:
        postgres = True

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def executescript(self, script):
            assert "CREATE TABLE IF NOT EXISTS cases" in script

    def fail_if_sqlite_lock_is_used(path):
        raise AssertionError(f"SQLite lock used for PostgreSQL target: {path}")

    monkeypatch.setattr(CaseRepository, "_connect", lambda self: FakePostgresConnection())
    monkeypatch.setattr(
        case_management,
        "_sqlite_initialization_lock",
        fail_if_sqlite_lock_is_used,
    )

    CaseRepository("postgresql://portal:secret@database.internal/security_portal")


def test_case_list_omits_untyped_null_filter_parameters(monkeypatch):
    captured = {}

    class EmptyCursor:
        def fetchall(self):
            return []

    class FakeConnection:
        postgres = True

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def execute(self, statement, parameters):
            captured["statement"] = statement
            captured["parameters"] = parameters
            return EmptyCursor()

    repository = CaseRepository.__new__(CaseRepository)
    repository.path = "postgresql://portal:secret@database.internal/security_portal"
    monkeypatch.setattr(repository, "_connect", lambda: FakeConnection())

    assert repository.list(limit=25, offset=5) == []
    assert "IS NULL" not in captured["statement"]
    assert captured["parameters"] == (25, 5)
