from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_tfe_alb_requires_explicit_restricted_cidrs() -> None:
    main = (ROOT / "terraform/modules/terraform-enterprise/main.tf").read_text(encoding="utf-8")
    variables = (ROOT / "terraform/modules/terraform-enterprise/variables.tf").read_text(encoding="utf-8")

    assert "cidr_blocks = var.alb_allowed_cidr_blocks" in main
    assert "length(var.alb_allowed_cidr_blocks) > 0" in main
    assert 'trimspace(cidr) != "0.0.0.0/0"' in variables
    assert 'trimspace(cidr) != "::/0"' in variables
    alb = main[
        main.index('resource "aws_security_group" "alb"') : main.index(
            'resource "aws_security_group" "tfe"'
        )
    ]
    assert alb.count("cidr_blocks = var.alb_allowed_cidr_blocks") == 2
    assert 'description = "HTTP"' not in alb
    assert 'description = "HTTPS"' not in alb


def test_tfe_readiness_accepts_only_http_200_and_exports_public_cert() -> None:
    main = (ROOT / "terraform/modules/terraform-enterprise/main.tf").read_text(encoding="utf-8")
    outputs = (ROOT / "terraform/modules/terraform-enterprise/outputs.tf").read_text(encoding="utf-8")

    assert 'path                = "/api/v1/health/readiness"' in main
    assert 'matcher             = "200"' in main
    assert 'matcher             = "200-499"' not in main
    assert 'output "alb_certificate_pem"' in outputs
