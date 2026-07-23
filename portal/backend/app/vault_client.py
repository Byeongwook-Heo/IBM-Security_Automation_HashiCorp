from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx

from .safe_data import safe_public_error, sanitize_data

_SAFE_VAULT_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_HEALTH_STATUS_CODES = {200, 429, 472, 473, 501, 503}
_HEALTH_FIELDS = {
    "initialized",
    "sealed",
    "standby",
    "performance_standby",
    "replication_performance_mode",
    "replication_dr_mode",
    "server_time_utc",
    "version",
    "cluster_name",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _env_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _validated_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    if not candidate:
        return ""
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("VAULT_ADDR is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("VAULT_ADDR must be an http(s) origin without credentials")
    return candidate


def _safe_path(value: str, *, name: str) -> str:
    candidate = value.strip().strip("/")
    if not candidate or not _SAFE_VAULT_PATH.fullmatch(candidate):
        raise ValueError(f"{name} contains unsupported characters")
    return candidate


def _read_secret_file(path_value: str | None) -> str:
    if not path_value:
        raise VaultClientError("authentication", "unconfigured")
    path = Path(path_value).expanduser()
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise VaultClientError("authentication", "unconfigured")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise VaultClientError("authentication", "unconfigured") from exc
    if not value:
        raise VaultClientError("authentication", "unconfigured")
    return value


def _read_aws_secret(
    secret_id: str | None,
    *,
    region: str | None,
    preferred_keys: tuple[str, ...],
) -> str:
    if not secret_id:
        raise VaultClientError("authentication", "unconfigured")
    try:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "secretsmanager",
            region_name=region or None,
            config=Config(
                connect_timeout=3,
                read_timeout=3,
                retries={"max_attempts": 2, "mode": "standard"},
            ),
        )
        payload = client.get_secret_value(SecretId=secret_id)
        value = payload.get("SecretString")
        if value is None and payload.get("SecretBinary") is not None:
            binary = payload["SecretBinary"]
            value = binary.decode("utf-8") if isinstance(binary, bytes) else str(binary)
    except Exception as exc:
        raise VaultClientError("authentication", "unreachable") from exc
    if not isinstance(value, str) or not value.strip():
        raise VaultClientError("authentication", "invalid_response")
    candidate = value.strip()
    if candidate.startswith("{"):
        try:
            document = json.loads(candidate)
        except ValueError as exc:
            raise VaultClientError("authentication", "invalid_response") from exc
        if not isinstance(document, dict):
            raise VaultClientError("authentication", "invalid_response")
        for key in preferred_keys:
            selected = document.get(key)
            if isinstance(selected, str) and selected.strip():
                return selected.strip()
        raise VaultClientError("authentication", "invalid_response")
    return candidate


@dataclass(frozen=True)
class VaultClientConfig:
    address: str
    namespace: str | None
    auth_method: str
    token_file: str | None
    approle_role_id: str | None
    approle_role_id_file: str | None
    approle_role_id_secret_id: str | None
    approle_secret_id: str | None
    approle_secret_id_file: str | None
    approle_secret_id_secret_id: str | None
    approle_mount: str
    aws_region: str | None
    jwt_role: str | None
    jwt_file: str | None
    jwt_mount: str
    pki_mount: str
    lease_prefix: str | None
    ca_cert: str | None
    timeout_seconds: float

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "VaultClientConfig":
        env = environ if environ is not None else os.environ
        address = _validated_url(env.get("VAULT_ADDR", ""))
        auth_method = env.get("VAULT_AUTH_METHOD", "").strip().lower().replace("-", "_")
        if not auth_method:
            if env.get("VAULT_TOKEN_FILE"):
                auth_method = "token_file"
            elif any(
                env.get(name)
                for name in (
                    "VAULT_APPROLE_ROLE_ID",
                    "VAULT_ROLE_ID",
                    "VAULT_APPROLE_ROLE_ID_FILE",
                    "VAULT_ROLE_ID_FILE",
                )
            ):
                auth_method = "approle"
            elif env.get("VAULT_JWT_FILE"):
                auth_method = "jwt"
            elif address:
                auth_method = "approle"
            else:
                auth_method = "none"
        if auth_method not in {"none", "token_file", "approle", "jwt"}:
            raise ValueError("VAULT_AUTH_METHOD is unsupported")
        timeout_value = env.get("VAULT_TIMEOUT_SECONDS", "5")
        try:
            timeout_seconds = min(max(float(timeout_value), 0.5), 30.0)
        except ValueError as exc:
            raise ValueError("VAULT_TIMEOUT_SECONDS is invalid") from exc

        pki_mount = _safe_path(env.get("VAULT_PKI_MOUNT", "pki"), name="VAULT_PKI_MOUNT")
        lease_prefix_value = env.get("VAULT_LEASE_PREFIX", "").strip()
        lease_prefix = (
            _safe_path(lease_prefix_value, name="VAULT_LEASE_PREFIX")
            if lease_prefix_value
            else None
        )
        return cls(
            address=address,
            namespace=env.get("VAULT_NAMESPACE", "").strip() or None,
            auth_method=auth_method,
            token_file=env.get("VAULT_TOKEN_FILE"),
            approle_role_id=env.get("VAULT_APPROLE_ROLE_ID") or env.get("VAULT_ROLE_ID"),
            approle_role_id_file=env.get("VAULT_APPROLE_ROLE_ID_FILE")
            or env.get("VAULT_ROLE_ID_FILE"),
            approle_role_id_secret_id=env.get(
                "VAULT_APPROLE_ROLE_ID_SECRET_ID",
                "security-portal-test/vault/readonly-role-id",
            ).strip()
            or None,
            approle_secret_id=env.get("VAULT_APPROLE_SECRET_ID") or env.get("VAULT_SECRET_ID"),
            approle_secret_id_file=env.get("VAULT_APPROLE_SECRET_ID_FILE")
            or env.get("VAULT_SECRET_ID_FILE"),
            approle_secret_id_secret_id=env.get(
                "VAULT_APPROLE_SECRET_ID_SECRET_ID",
                "security-portal-test/vault/readonly-secret-id",
            ).strip()
            or None,
            approle_mount=_safe_path(
                env.get("VAULT_APPROLE_AUTH_MOUNT", "approle"),
                name="VAULT_APPROLE_AUTH_MOUNT",
            ),
            aws_region=env.get("VAULT_AWS_REGION")
            or env.get("AWS_REGION")
            or env.get("AWS_DEFAULT_REGION"),
            jwt_role=env.get("VAULT_JWT_ROLE", "").strip() or None,
            jwt_file=env.get("VAULT_JWT_FILE"),
            jwt_mount=_safe_path(
                env.get("VAULT_JWT_AUTH_MOUNT", "jwt"),
                name="VAULT_JWT_AUTH_MOUNT",
            ),
            pki_mount=pki_mount,
            lease_prefix=lease_prefix,
            ca_cert=env.get("VAULT_CACERT", "").strip() or None,
            timeout_seconds=timeout_seconds,
        )


class VaultClientError(RuntimeError):
    def __init__(self, component: str, code: str):
        super().__init__(f"{component}:{code}")
        self.component = component
        self.code = code


class VaultReadOnlyClient:
    def __init__(self, config: VaultClientConfig):
        self.config = config

    @property
    def configured(self) -> bool:
        return bool(self.config.address)

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        allowed_status: Iterable[int] = (200,),
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        if self.config.namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        verify: bool | str = self.config.ca_cert or True
        try:
            with httpx.Client(
                timeout=self.config.timeout_seconds,
                verify=verify,
                follow_redirects=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self.config.address}/v1/{path.lstrip('/')}",
                    headers=headers,
                    json=json_body,
                )
        except (httpx.HTTPError, OSError) as exc:
            raise VaultClientError("connection", "unreachable") from exc
        if response.status_code not in set(allowed_status):
            code = "unauthorized" if response.status_code in {401, 403} else "invalid_response"
            raise VaultClientError("authorization", code)
        try:
            data = response.json()
        except ValueError as exc:
            raise VaultClientError("response", "invalid_response") from exc
        if not isinstance(data, dict):
            raise VaultClientError("response", "invalid_response")
        return data

    def _value_or_file_or_aws(
        self,
        value: str | None,
        file_path: str | None,
        aws_secret_id: str | None,
        *,
        preferred_keys: tuple[str, ...],
    ) -> str:
        if value and value.strip():
            return value.strip()
        if file_path:
            return _read_secret_file(file_path)
        return _read_aws_secret(
            aws_secret_id,
            region=self.config.aws_region,
            preferred_keys=preferred_keys,
        )

    def _login_token(self) -> str | None:
        method = self.config.auth_method
        if method == "none":
            return None
        if method == "token_file":
            return _read_secret_file(self.config.token_file)
        if method == "approle":
            role_id = self._value_or_file_or_aws(
                self.config.approle_role_id,
                self.config.approle_role_id_file,
                self.config.approle_role_id_secret_id,
                preferred_keys=("role_id", "value"),
            )
            secret_id = self._value_or_file_or_aws(
                self.config.approle_secret_id,
                self.config.approle_secret_id_file,
                self.config.approle_secret_id_secret_id,
                preferred_keys=("secret_id", "value"),
            )
            payload = self._request(
                "POST",
                f"auth/{self.config.approle_mount}/login",
                json_body={"role_id": role_id, "secret_id": secret_id},
            )
        else:
            if not self.config.jwt_role:
                raise VaultClientError("authentication", "unconfigured")
            payload = self._request(
                "POST",
                f"auth/{self.config.jwt_mount}/login",
                json_body={
                    "role": self.config.jwt_role,
                    "jwt": _read_secret_file(self.config.jwt_file),
                },
            )
        token = payload.get("auth", {}).get("client_token")
        if not isinstance(token, str) or not token.strip():
            raise VaultClientError("authentication", "invalid_response")
        return token.strip()

    @staticmethod
    def _list_keys(payload: dict[str, Any]) -> list[str]:
        keys = payload.get("data", {}).get("keys", [])
        if not isinstance(keys, list):
            return []
        return [str(key) for key in keys if isinstance(key, (str, int))]

    def _pki_metadata(self, token: str) -> dict[str, Any]:
        mount = self.config.pki_mount
        certificates = self._list_keys(
            self._request("LIST", f"{mount}/certs", token=token)
        )
        issuer_payload = self._request("LIST", f"{mount}/issuers", token=token)
        issuers = self._list_keys(issuer_payload)
        try:
            roles = self._list_keys(
                self._request("LIST", f"{mount}/roles", token=token)
            )
        except VaultClientError:
            roles = []
        key_info = issuer_payload.get("data", {}).get("key_info", {})
        issuer_metadata = []
        for issuer_id in issuers[:50]:
            info = key_info.get(issuer_id, {}) if isinstance(key_info, dict) else {}
            issuer_metadata.append(
                sanitize_data(
                    {
                        "issuer_id": issuer_id,
                        "issuer_name": info.get("issuer_name") if isinstance(info, dict) else None,
                        "key_id": info.get("key_id") if isinstance(info, dict) else None,
                    },
                    max_items=10,
                )
            )
        default_issuer = None
        try:
            config_payload = self._request("GET", f"{mount}/config/issuers", token=token)
            candidate = config_payload.get("data", {}).get("default")
            if isinstance(candidate, str):
                default_issuer = candidate[:200]
        except VaultClientError:
            pass
        return {
            "status": "live",
            "mount": mount,
            "certificate_count": len(certificates),
            "issuer_count": len(issuers),
            "role_count": len(roles),
            "issuers": issuer_metadata,
            "default_issuer": default_issuer,
            "inventory_truncated": len(issuers) > 50,
        }

    def _runtime_metadata(self, token: str) -> dict[str, Any]:
        token_payload = self._request("GET", "auth/token/lookup-self", token=token)
        token_data = token_payload.get("data", {})
        mounts_payload = self._request("GET", "sys/mounts", token=token)
        mounts = mounts_payload.get("data", {})
        if not isinstance(token_data, dict) or not isinstance(mounts, dict):
            raise VaultClientError("runtime", "invalid_response")
        policies = token_data.get("policies", [])
        return {
            "status": "live",
            "identity": {
                "ttl_seconds": token_data.get("ttl")
                if isinstance(token_data.get("ttl"), (int, float))
                else None,
                "renewable": token_data.get("renewable")
                if isinstance(token_data.get("renewable"), bool)
                else None,
                "orphan": token_data.get("orphan")
                if isinstance(token_data.get("orphan"), bool)
                else None,
                "policy_count": len(policies) if isinstance(policies, list) else 0,
            },
            "mount_count": len(mounts),
            "pki_mount_configured": f"{self.config.pki_mount}/" in mounts,
        }

    def _lease_count(self, token: str) -> dict[str, Any]:
        prefix = self.config.lease_prefix
        if not prefix:
            return {
                "status": "not_configured",
                "prefix_configured": False,
                "lease_count": None,
            }
        pending = [(prefix, 0)]
        lease_count = 0
        visited = 0
        truncated = False
        while pending:
            current, depth = pending.pop()
            keys = self._list_keys(
                self._request("LIST", f"sys/leases/lookup/{current}", token=token)
            )
            for key in keys:
                visited += 1
                if visited > 500:
                    truncated = True
                    pending.clear()
                    break
                if key.endswith("/") and depth < 4:
                    pending.append((f"{current.rstrip('/')}/{key.rstrip('/')}", depth + 1))
                else:
                    lease_count += 1
        return {
            "status": "live",
            "prefix_configured": True,
            "lease_count": lease_count,
            "inventory_truncated": truncated,
        }

    def collect_metadata(self) -> dict[str, Any]:
        observed_at = _utc_now()
        base: dict[str, Any] = {
            "configured": self.configured,
            "status": "unconfigured",
            "auth_method": self.config.auth_method,
            "namespace_configured": self.config.namespace is not None,
            "observed_at": observed_at,
            "provenance": {
                "source": "vault-api",
                "mode": "read-only",
                "observed_at": observed_at,
            },
            "health": {"status": "unconfigured"},
            "runtime": {"status": "unconfigured"},
            "pki": {"status": "unconfigured"},
            "leases": {"status": "unconfigured"},
            "errors": [],
        }
        if not self.configured:
            base["errors"] = [safe_public_error("connection", "unconfigured")]
            return base

        try:
            health_payload = self._request(
                "GET",
                "sys/health",
                allowed_status=_HEALTH_STATUS_CODES,
            )
            health = {
                key: health_payload.get(key)
                for key in _HEALTH_FIELDS
                if key in health_payload
            }
            health["status"] = "sealed" if health.get("sealed") else "live"
            base["health"] = sanitize_data(health)
        except VaultClientError as exc:
            base["status"] = "unreachable"
            base["health"] = {"status": exc.code}
            base["errors"] = [safe_public_error(exc.component, exc.code)]
            return base

        if base["health"].get("sealed"):
            base["status"] = "sealed"
            base["errors"] = [safe_public_error("health", "sealed")]
            return base

        try:
            token = self._login_token()
        except VaultClientError as exc:
            base["status"] = "partial"
            base["pki"] = {"status": exc.code}
            base["runtime"] = {"status": exc.code}
            base["leases"] = {"status": exc.code}
            base["errors"] = [safe_public_error(exc.component, exc.code)]
            return base
        if not token:
            base["status"] = "partial"
            base["pki"] = {"status": "authentication_not_configured"}
            base["runtime"] = {"status": "authentication_not_configured"}
            base["leases"] = {"status": "authentication_not_configured"}
            base["errors"] = [safe_public_error("authentication", "unconfigured")]
            return base

        component_errors = []
        try:
            base["runtime"] = self._runtime_metadata(token)
        except VaultClientError as exc:
            base["runtime"] = {"status": exc.code}
            component_errors.append(safe_public_error("runtime", exc.code))
        try:
            base["pki"] = self._pki_metadata(token)
        except VaultClientError as exc:
            base["pki"] = {"status": exc.code, "mount": self.config.pki_mount}
            component_errors.append(safe_public_error("pki", exc.code))
        try:
            base["leases"] = self._lease_count(token)
        except VaultClientError as exc:
            base["leases"] = {
                "status": exc.code,
                "prefix_configured": self.config.lease_prefix is not None,
                "lease_count": None,
            }
            component_errors.append(safe_public_error("leases", exc.code))
        base["errors"] = component_errors
        base["status"] = "live" if not component_errors else "partial"
        return sanitize_data(base)


def collect_vault_metadata(environ: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        config = VaultClientConfig.from_env(environ)
    except ValueError:
        observed_at = _utc_now()
        return {
            "configured": bool((environ or os.environ).get("VAULT_ADDR")),
            "status": "unconfigured",
            "auth_method": "invalid",
            "namespace_configured": False,
            "observed_at": observed_at,
            "provenance": {
                "source": "vault-api",
                "mode": "read-only",
                "observed_at": observed_at,
            },
            "health": {"status": "invalid_configuration"},
            "runtime": {"status": "invalid_configuration"},
            "pki": {"status": "invalid_configuration"},
            "leases": {"status": "invalid_configuration"},
            "errors": [safe_public_error("configuration", "unconfigured")],
        }
    return VaultReadOnlyClient(config).collect_metadata()
