from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from connectors.common import redact_sensitive
from connectors.qradar.sender import send as send_qradar
from connectors.elastic.sender import send_many as send_elastic


PRODUCTS: dict[str, tuple[str, str]] = {
    "aws-security": ("aws-security/real.py", "RealAwsSecurityConnector"),
    "boundary": ("boundary/real.py", "RealBoundaryConnector"),
    "concert": ("concert/real.py", "RealConcertConnector"),
    "guardium": ("guardium/real.py", "RealGuardiumConnector"),
    "instana": ("instana/real.py", "RealInstanaConnector"),
    "kubecost": ("kubecost/real.py", "RealKubecostConnector"),
    "postgresql-pgaudit": ("postgresql-pgaudit/real.py", "RealPostgresqlPgauditConnector"),
    "turbonomic": ("turbonomic/real.py", "RealTurbonomicConnector"),
    "vault": ("vault/real.py", "RealVaultConnector"),
    "vault-audit": ("vault-audit/real.py", "RealVaultAuditConnector"),
    "vault-radar": ("vault-radar/real.py", "RealVaultRadarConnector"),
    "verify": ("verify/real.py", "RealVerifyConnector"),
}


def load_connector(product: str):
    relative_path, class_name = PRODUCTS[product]
    module_path = Path(__file__).resolve().parent / relative_path
    module_name = f"connector_{product.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load connector module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, class_name)()


def collect_product(product: str) -> list[dict[str, Any]]:
    connector = load_connector(product)
    return connector.collect()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run real product connectors.")
    parser.add_argument("product", choices=sorted(PRODUCTS.keys()) + ["all"])
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--qradar-host", default="")
    parser.add_argument("--qradar-port", type=int, default=514)
    parser.add_argument("--qradar-live", action="store_true")
    parser.add_argument("--elastic-url", default="")
    parser.add_argument("--elastic-api-key", default="")
    parser.add_argument("--elastic-live", action="store_true")
    parser.add_argument("--include-events", action="store_true", help="Include redacted normalized events in stdout.")
    args = parser.parse_args(argv)

    products = sorted(PRODUCTS) if args.product == "all" else [args.product]
    output: dict[str, Any] = {}
    for product in products:
        events = collect_product(product)[: args.limit]
        qradar = [
            send_qradar(
                event,
                host=args.qradar_host or None,
                port=args.qradar_port,
                dry_run=not args.qradar_live,
            )
            for event in events
        ]
        elastic = send_elastic(
            events,
            base_url=args.elastic_url or None,
            api_key=args.elastic_api_key or None,
            dry_run=not args.elastic_live,
        )
        product_output: dict[str, Any] = {
            "event_count": len(events),
            "qradar": qradar,
            "elastic": elastic,
        }
        if args.include_events:
            product_output["events"] = [redact_sensitive(event) for event in events]
        output[product] = product_output

    print(json.dumps(output, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
