from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_stateful_hosts_are_not_replaced_for_user_data_changes() -> None:
    for module in ("elastic-siem", "terraform-enterprise", "observability-stack"):
        main = (ROOT / "terraform/modules" / module / "main.tf").read_text(encoding="utf-8")
        instance = main.split('resource "aws_instance" "this" {', 1)[1]
        assert "user_data_replace_on_change = false" in main
        assert "ignore_changes = [user_data]" in instance
