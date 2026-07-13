from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
OPTIMIZATION_DIR = REPO_ROOT / "k8s" / "optimization"
SENSITIVE_RESOURCES = {"secret", "secrets", "serviceaccounts/token"}


def _read(name: str) -> str:
    return (OPTIMIZATION_DIR / name).read_text(encoding="utf-8")


def _inline_lists(text: str, key: str) -> list[list[str]]:
    matches = re.findall(rf"^\s*{re.escape(key)}:\s*(\[[^\n]+\])\s*$", text, re.MULTILINE)
    return [json.loads(match) for match in matches]


@pytest.mark.skipif(shutil.which("ruby") is None, reason="Ruby/Psych is unavailable")
def test_optimization_yaml_is_syntactically_valid():
    yaml_files = sorted(OPTIMIZATION_DIR.glob("*.yaml"))
    result = subprocess.run(
        [
            "ruby",
            "-e",
            'require "yaml"; ARGV.each { |path| YAML.load_stream(File.read(path)) }',
            *(str(path) for path in yaml_files),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_krr_rbac_is_namespace_limited_and_read_only():
    rbac = _read("krr-rbac.example.yaml")
    verbs = {verb for values in _inline_lists(rbac, "verbs") for verb in values}
    resources = {
        resource for values in _inline_lists(rbac, "resources") for resource in values
    }

    assert verbs == {"get", "list"}
    assert not resources & SENSITIVE_RESOURCES
    assert "secrets" not in rbac.lower()
    assert "automountServiceAccountToken: false" in rbac
    assert "kind: Role\n" in rbac
    assert "name: krr-workload-readonly\n  namespace: security-lab" in rbac
    assert 'resources: ["namespaces", "nodes"]' in rbac
    assert "ClusterRoleBinding" in rbac


def test_krr_cronjob_is_pinned_hardened_and_recommendation_only():
    cronjob = _read("krr-cronjob.example.yaml")

    assert "image: robustadev/krr:v1.28.0" in cronjob
    assert ":latest" not in cronjob
    assert 'command: ["python", "krr.py"]' in cronjob
    assert "- --namespace\n                - $(POD_NAMESPACE)" in cronjob
    assert "- --formatter\n                - json" in cronjob
    assert "- --prometheus-url\n                - $(PROMETHEUS_URL)" in cronjob
    assert "optimization.security-lab/mode: recommendation-only" in cronjob
    assert "readOnlyRootFilesystem: true" in cronjob
    assert "allowPrivilegeEscalation: false" in cronjob
    assert "runAsNonRoot: true" in cronjob
    assert 'drop: ["ALL"]' in cronjob
    assert "secretKeyRef" not in cronjob
    assert "enforcer" not in cronjob.lower()
    assert "kubectl apply" not in cronjob


def test_goldilocks_installs_only_the_vpa_recommender():
    values = _read("goldilocks-values.yaml")

    assert re.search(r"vpa:\n  enabled: true", values)
    assert re.search(r"  updater:\n    enabled: false", values)
    assert re.search(r"  admissionController:\n    enabled: false", values)
    assert re.search(r"  recommender:\n    enabled: true", values)
    assert re.search(r"controller:.*?on-by-default: false", values, re.DOTALL)
    assert re.search(r"dashboard:\n  enabled: false", values)
    assert "enableArgoproj: false" in values


def test_vpa_examples_are_explicitly_recommendation_only():
    vpa = _read("vpa-recommendation-only.example.yaml")
    namespace = _read("goldilocks-namespace.example.yaml")

    assert 'updateMode: "Off"' in vpa
    assert "controlledValues: RequestsOnly" in vpa
    assert 'controlledResources: ["cpu", "memory"]' in vpa
    assert 'goldilocks.fairwinds.com/enabled: "true"' in namespace
    assert 'goldilocks.fairwinds.com/vpa-update-mode: "Off"' in namespace
    assert "name: security-lab" in namespace


def test_vpa_collector_reads_only_allowlisted_recommendation_fields():
    collector = _read("vpa-recommendation-collector.example.yaml")
    verbs = {verb for values in _inline_lists(collector, "verbs") for verb in values}
    resources = {
        resource for values in _inline_lists(collector, "resources") for resource in values
    }

    assert verbs == {"get", "list"}
    assert resources == {"verticalpodautoscalers"}
    assert "ClusterRole" not in collector
    assert "--output=custom-columns=" in collector
    assert "TARGET_CPU:" in collector
    assert "TARGET_MEMORY:" in collector
    assert "LOWER_CPU:" in collector
    assert "UPPER_MEMORY:" in collector
    assert "--output=json" not in collector
    assert "annotations:.metadata.annotations" not in collector
    assert "secretKeyRef" not in collector
    assert "automountServiceAccountToken: false" in collector
    assert "automountServiceAccountToken: true" in collector
    assert "readOnlyRootFilesystem: true" in collector
    assert "allowPrivilegeEscalation: false" in collector


def test_installation_path_does_not_apply_karpenter():
    readme = _read("README.md")
    install_section = readme.split("## Installation", maxsplit=1)[1]

    assert "vertical-pod-autoscaler-1.6.0" in install_section
    assert "/master/" not in install_section
    assert "karpenter-nodepool.example.yaml" not in install_section
    assert "does not deploy Karpenter" in readme
