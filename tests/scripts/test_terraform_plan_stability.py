from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_rds_boolean_parameters_use_provider_normalized_values() -> None:
    main = (ROOT / "terraform/modules/data-security-lab/main.tf").read_text(encoding="utf-8")

    for variable in (
        "pgaudit_log_catalog",
        "pgaudit_log_parameter",
        "pgaudit_log_statement_once",
        "log_connections",
        "log_disconnections",
    ):
        assert f'var.{variable} ? "1" : "0"' in main
